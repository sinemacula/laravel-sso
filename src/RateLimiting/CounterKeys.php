<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;

/**
 * The keys the attempt limiter stores its counters under (SSO-11.8):
 * HMAC-SHA256 digests of the flow, the scope and the value counted, in its
 * canonical form, keyed with a key derived from the application key
 * (`app.key`).
 *
 * What a counter counts (an IP address, an email domain, a connection id) is
 * easy to enumerate, so a plain digest of it could be reversed by anyone who
 * reads the table, from a backup or a replica, say, by hashing every candidate.
 * A keyed digest cannot be recomputed without the application key, and stays
 * deterministic, so every server counts in the same row. Rotating the
 * application key starts every counter afresh.
 *
 * A value is counted in the form that stands for one client or one domain, so
 * it cannot be spread over several counters by writing it another way:
 *
 * - an IP address: an IPv4 address in dotted decimal, an IPv4-mapped or NAT64
 *   IPv6 address as the IPv4 address it carries, and any other IPv6 address as
 *   the /64 network it belongs to (a client is usually given a whole /64); a
 *   value that is not an IP address is counted lower-cased as given;
 * - an email domain: lower-cased, with one trailing dot removed, and converted
 *   to ASCII by IDNA (UTS 46, non-transitional); a value that will not convert
 *   is counted lower-cased as given;
 * - a connection id: as given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CounterKeys
{
    /** @var string What the key derived from the application key is for, so it is used for nothing else. */
    private const string PURPOSE = 'laravel-sso rate limit counters';

    /** @var list<string> The first twelve bytes of the IPv6 prefixes whose last four carry an IPv4 client's address: IPv4-mapped (`::ffff:0:0/96`) and the NAT64 well-known prefix (`64:ff9b::/96`). */
    private const array IPV4_CARRYING_PREFIXES = ["\0\0\0\0\0\0\0\0\0\0\xff\xff", "\0\x64\xff\x9b\0\0\0\0\0\0\0\0"];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the application key is read from on every call. */
        private Repository $config,
    ) {}

    /**
     * The key of the counter for a flow, a scope and a value, as 64 lower-case
     * hexadecimal characters.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow  $flow
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope  $scope
     * @param  string  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function counter(AttemptFlow $flow, AttemptScope $scope, #[\SensitiveParameter] string $value): string
    {
        $parts = [$flow->value, $scope->value, self::canonical($scope, $value)];

        return hash_hmac('sha256', implode("\0", $parts), $this->secret());
    }

    /**
     * The canonical form of a value counted in the scope.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope  $scope
     * @param  string  $value
     * @return string
     */
    private static function canonical(AttemptScope $scope, #[\SensitiveParameter] string $value): string
    {
        return match ($scope) {
            AttemptScope::PER_IP           => self::canonicalIp($value),
            AttemptScope::PER_EMAIL_DOMAIN => self::canonicalDomain($value),
            AttemptScope::PER_CONNECTION   => $value,
        };
    }

    /**
     * The canonical form of an IP address: an IPv4 address, or the IPv4 address
     * an IPv6 address carries (IPv4-mapped, or translated through the NAT64
     * well-known prefix, as a server reached only over IPv6 sees every IPv4
     * client), in dotted decimal; any other IPv6 address as the /64 network it
     * belongs to. Anything that is not an IP address is lower-cased.
     *
     * @param  string  $ip
     * @return string
     */
    private static function canonicalIp(#[\SensitiveParameter] string $ip): string
    {
        $packed = inet_pton($ip);

        if ($packed === false) {
            return strtolower($ip);
        }

        if (in_array(substr($packed, 0, 12), self::IPV4_CARRYING_PREFIXES, true)) {
            $packed = substr($packed, 12);
        }

        return strlen($packed) === 4
            ? (string) inet_ntop($packed)
            : inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8)) . '/64';
    }

    /**
     * The canonical form of an email domain: lower-cased, with one trailing dot
     * removed, in ASCII (UTS 46, non-transitional); lower-cased as given when
     * it will not convert.
     *
     * @param  string  $domain
     * @return string
     */
    private static function canonicalDomain(#[\SensitiveParameter] string $domain): string
    {
        $lower   = strtolower($domain);
        $trimmed = str_ends_with($lower, '.') ? substr($lower, 0, -1) : $lower;

        // An empty domain is refused by `idn_to_ascii()` with an error, not a
        // `false`, so it is counted as given before it is converted
        $ascii = $trimmed === '' ? false : idn_to_ascii($trimmed, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);

        return $ascii === false ? $lower : strtolower($ascii);
    }

    /**
     * The key the digests are made with, derived from the application key.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function secret(): string
    {
        $key = $this->config->get('app.key');

        if (!is_string($key) || $key === '') {
            throw new \InvalidArgumentException('The attempt limiter keys its counters with the application key; set `app.key`.');
        }

        return hash_hmac('sha256', self::PURPOSE, $key, true);
    }
}
