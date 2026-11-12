<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OutboundRequests;

use Illuminate\Process\Exceptions\ProcessTimedOutException;
use Illuminate\Support\Facades\Process;
use SineMacula\Laravel\Sso\Contracts\HostResolver;

/**
 * A host resolver that asks `dig`, whose timeout bounds each lookup; a name not
 * resolved in time answers `[]`, which the fetcher fails as `fetch_failed`.
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

    /** @var int The seconds one lookup may take, should `dig` overrun its bound. */
    public const int LOOKUP_SECONDS = 3;

    /**
     * Every A and AAAA address, or `[]` when neither lookup answered in time.
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
     * The IP literals `dig` prints for the record type; the name is asked as
     * absolute so no search domain is appended.
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
