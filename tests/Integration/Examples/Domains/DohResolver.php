<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Domains;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Domains\DnsLookup;

/**
 * A DNS over HTTPS resolver with its own deadline; any answer but `NOERROR` or
 * `NXDOMAIN` is `lookupFailed()`, since it proves nothing either way.
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
     * The TXT records at the name, asked as absolute so no search domain
     * answers.
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
     * The answer's TXT record with its strings joined, or `null` for another
     * type.
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
     * The record's quoted character-strings, joined and unescaped; the data as
     * given when it quotes none.
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
