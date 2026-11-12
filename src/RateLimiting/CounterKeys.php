<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Sso\RateLimiting\Enums\AttemptScope;

/**
 * Counter keys: HMAC-SHA256 of the canonical value, keyed from `app.key`, since
 * a plain digest of an IP or domain is reversible by enumeration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CounterKeys
{
    /** @var string Domain separation for the key derived from `app.key`. */
    private const string PURPOSE = 'laravel-sso rate limit counters';

    /** @var list<string> IPv4-mapped (`::ffff:0:0/96`) and NAT64 (`64:ff9b::/96`) prefixes. */
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
     * The counter key, as 64 lower-case hex characters.
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
     * The form standing for one client or domain, so it cannot be spread over
     * several counters by writing it another way.
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
     * IPv4 in dotted decimal, including one carried in IPv6; other IPv6 as its
     * /64, since a client is usually given a whole /64.
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
     * Lower-cased, trailing dot removed, in IDNA ASCII when it converts.
     *
     * @param  string  $domain
     * @return string
     */
    private static function canonicalDomain(#[\SensitiveParameter] string $domain): string
    {
        $lower   = strtolower($domain);
        $trimmed = str_ends_with($lower, '.') ? substr($lower, 0, -1) : $lower;

        // `idn_to_ascii()` raises an error, not `false`, for an empty domain
        $ascii = $trimmed === '' ? false : idn_to_ascii($trimmed, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);

        return $ascii === false ? $lower : strtolower($ascii);
    }

    /**
     * The HMAC key, derived from the application key.
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
