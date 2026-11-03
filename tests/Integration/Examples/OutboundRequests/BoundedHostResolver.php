<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OutboundRequests;

use Illuminate\Process\Exceptions\ProcessTimedOutException;
use Illuminate\Support\Facades\Process;
use SineMacula\Laravel\Sso\Contracts\HostResolver;

/**
 * The application's own host resolver for the package's fetcher (SSO-2.9): it
 * asks `dig`, a DNS client with its own timeout, for the name's A and then its
 * AAAA records, each lookup waiting at most `ANSWER_SECONDS` for one try, and
 * stopped by the process's own timeout should `dig` overrun that. A lookup that
 * times out, fails or finds nothing adds no address, so a name that cannot be
 * resolved in time answers `[]`, which the fetcher fails as `fetch_failed`
 * without sending anything. Only IP literals are answered: the name a CNAME
 * record points to, and anything else `dig` prints, is dropped.
 *
 * It keeps nothing between lookups, so the application binds it as a singleton.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BoundedHostResolver implements HostResolver
{
    /** @var int The seconds `dig` waits for an answer, on its one try. */
    public const int ANSWER_SECONDS = 2;

    /** @var int The seconds one lookup may take in all, should `dig` overrun its own bound. */
    public const int LOOKUP_SECONDS = 3;

    /**
     * Every A and AAAA address of the host name, `[]` when there is none or
     * neither lookup answered in time.
     *
     * @param  string  $asciiHost
     * @return list<string>
     */
    #[\Override]
    public function addresses(string $asciiHost): array
    {
        return [...self::lookup($asciiHost, 'A'), ...self::lookup($asciiHost, 'AAAA')];
    }

    /**
     * The addresses of the record type at the name, asked as an absolute name
     * so no search domain is appended, or `[]` when the lookup timed out or
     * failed.
     *
     * @param  string  $asciiHost
     * @param  string  $type
     * @return list<string>
     */
    private static function lookup(string $asciiHost, string $type): array
    {
        $command = ['dig', '+short', '+time=' . self::ANSWER_SECONDS, '+tries=1', $type, rtrim($asciiHost, '.') . '.'];

        try {
            $result = Process::timeout(self::LOOKUP_SECONDS)->run($command);
        } catch (ProcessTimedOutException) {
            return [];
        }

        $lines = $result->successful() ? preg_split('/\R/', trim($result->output())) : false;

        return array_values(array_filter($lines ?: [], static fn (string $line): bool => filter_var($line, FILTER_VALIDATE_IP) !== false));
    }
}
