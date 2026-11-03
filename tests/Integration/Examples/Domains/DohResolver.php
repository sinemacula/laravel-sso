<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Domains;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Domains\DnsLookup;

/**
 * The example application's own DNS resolver (SSO-3.2): it asks a DNS over
 * HTTPS service for the TXT records at a name, through its JSON interface, with
 * a deadline of its own, in place of the package's default, which asks the
 * system resolver with none.
 *
 * It asks for the name as absolute (with a trailing dot), so no search domain
 * answers for it. An answer of `NOERROR` is the TXT records it holds, each
 * record's character-strings joined (`absent` when it holds none); `NXDOMAIN`
 * is `absent`; any other answer, an error status, a body it cannot read or a
 * request that could not be made, a failed connection among them, is
 * `lookupFailed()`, since it proves nothing either way. It keeps nothing of one
 * lookup for the next, and logs no record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DohResolver implements DnsResolver
{
    /** @var string The DNS over HTTPS service's JSON endpoint. */
    public const string ENDPOINT = 'https://dns.example.net/dns-query';

    /** @var int How long a lookup may take, in seconds, connecting included. */
    private const int TIMEOUT_SECONDS = 2;

    /** @var int The DNS response code of an answer. */
    private const int NO_ERROR = 0;

    /** @var int The DNS response code of a name that does not exist. */
    private const int NON_EXISTENT_DOMAIN = 3;

    /** @var int The DNS type of a TXT record. */
    private const int TXT = 16;

    /**
     * The TXT records at the name, asked of the service.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Domains\DnsLookup
     */
    #[\Override]
    public function txt(string $name): DnsLookup
    {
        $response = rescue(static fn (): Response => Http::timeout(self::TIMEOUT_SECONDS)
            ->connectTimeout(self::TIMEOUT_SECONDS)
            ->accept('application/dns-json')
            ->get(self::ENDPOINT, ['name' => $name . '.', 'type' => 'TXT']), report: false);

        $body = $response?->successful() === true ? $response->json() : null;

        return is_array($body) ? self::lookup($body) : DnsLookup::lookupFailed();
    }

    /**
     * The lookup the service's answer says.
     *
     * @param  array<array-key, mixed>  $body
     * @return \SineMacula\Laravel\Sso\Domains\DnsLookup
     */
    private static function lookup(array $body): DnsLookup
    {
        $answers = is_array($body['Answer'] ?? null) ? $body['Answer'] : [];

        return match ($body['Status'] ?? null) {
            self::NO_ERROR            => self::records($answers),
            self::NON_EXISTENT_DOMAIN => DnsLookup::absent(),
            default                   => DnsLookup::lookupFailed(),
        };
    }

    /**
     * The TXT records among the answers, or `absent` when there are none.
     *
     * @param  array<array-key, mixed>  $answers
     * @return \SineMacula\Laravel\Sso\Domains\DnsLookup
     */
    private static function records(array $answers): DnsLookup
    {
        $records = array_values(array_filter(array_map(self::record(...), $answers), static fn (?string $record): bool => $record !== null));

        return $records === [] ? DnsLookup::absent() : DnsLookup::found($records);
    }

    /**
     * The answer's TXT record, its character-strings joined, or `null` when it
     * is not a TXT record.
     *
     * @param  mixed  $answer
     * @return ?string
     */
    private static function record(mixed $answer): ?string
    {
        if (!is_array($answer) || ($answer['type'] ?? null) !== self::TXT) {
            return null;
        }

        $data = $answer['data'] ?? null;

        return is_string($data) ? self::joined($data) : null;
    }

    /**
     * The record's character-strings, each quoted in the answer, joined and
     * unescaped; the data as given when it quotes none.
     *
     * @param  string  $data
     * @return string
     */
    private static function joined(string $data): string
    {
        preg_match_all('/"((?:[^"\\\]|\\\.)*)"/', $data, $strings);

        return $strings[1] === [] ? $data : stripslashes(implode('', $strings[1]));
    }
}
