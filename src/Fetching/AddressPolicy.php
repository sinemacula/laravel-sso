<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

/**
 * The IP addresses the outbound fetcher refuses, judged on their bytes and on
 * any IPv4 address an IPv6 address carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AddressPolicy
{
    /** @var list<string> The IPv4 ranges always refused. */
    public const array REFUSED_IPV4 = [
        '0.0.0.0/8',          // Current network (RFC 791)
        '10.0.0.0/8',         // Internal network (RFC 1918)
        '100.64.0.0/10',      // Shared address space, carrier-grade NAT (RFC 6598)
        '127.0.0.0/8',        // Loopback (RFC 1122)
        '169.254.0.0/16',     // Link-local and cloud metadata (RFC 3927)
        '172.16.0.0/12',      // Internal network (RFC 1918)
        '192.0.0.0/24',       // IETF protocol assignments (RFC 6890)
        '192.0.2.0/24',       // Documentation, TEST-NET-1 (RFC 5737)
        '192.88.99.0/24',     // 6to4 relay anycast (RFC 7526)
        '192.168.0.0/16',     // Internal network (RFC 1918)
        '198.18.0.0/15',      // Benchmarking (RFC 2544)
        '198.51.100.0/24',    // Documentation, TEST-NET-2 (RFC 5737)
        '203.0.113.0/24',     // Documentation, TEST-NET-3 (RFC 5737)
        '224.0.0.0/4',        // Multicast (RFC 5771)
        '240.0.0.0/4',        // Reserved (RFC 1112)
        '255.255.255.255/32', // Limited broadcast (RFC 919)
    ];

    /** @var list<string> The IPv6 ranges always refused. */
    public const array REFUSED_IPV6 = [
        '::/128',        // Unspecified (RFC 4291)
        '::1/128',       // Loopback (RFC 4291)
        '100::/64',      // Discard only (RFC 6666)
        '2001::/32',     // Teredo, whose IPv4 address is obfuscated (RFC 4380)
        '2001:db8::/32', // Documentation (RFC 3849)
        'fc00::/7',      // Unique local, cloud metadata among them (RFC 4193)
        'fe80::/10',     // Link-local (RFC 4291)
        'fec0::/10',     // Site-local, deprecated (RFC 3879)
        'ff00::/8',      // Multicast (RFC 4291)
    ];

    /** @var array<string, list<int>> The IPv6 ranges that carry an IPv4 address, with its byte offsets. */
    public const array IPV4_CARRIERS = [
        '::ffff:0:0/96'   => [12, 13, 14, 15], // IPv4-mapped (RFC 4291)
        '::/96'           => [12, 13, 14, 15], // IPv4-compatible (RFC 4291)
        '::ffff:0:0:0/96' => [12, 13, 14, 15], // IPv4-translated (RFC 2765)
        '64:ff9b::/96'    => [12, 13, 14, 15], // NAT64, well-known (RFC 6052)
        '64:ff9b:1::/48'  => [6, 7, 9, 10],    // NAT64, locally assigned (RFC 8215)
        '2002::/16'       => [2, 3, 4, 5],     // 6to4 (RFC 3056)
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetcherSettings  $settings
     */
    public function __construct(

        /** The settings the added ranges are read from. */
        private FetcherSettings $settings,
    ) {}

    /**
     * Whether the address is invalid, in a refused range or carries an IPv4
     * address that is.
     *
     * @param  string  $address
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isRefused(string $address): bool
    {
        $bytes = self::bytes($address);

        if ($bytes === null) {
            return true;
        }

        $ranges = [...self::REFUSED_IPV4, ...self::REFUSED_IPV6, ...$this->settings->refusedRanges()];

        foreach ([$bytes, ...self::carriedIpv4($bytes)] as $candidate) {
            if (self::isWithinAny($candidate, $ranges)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The address's `inet_pton()` bytes, or `null` for an invalid IP literal.
     *
     * @param  string  $address
     * @return ?string
     */
    private static function bytes(string $address): ?string
    {
        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $bytes = inet_pton($address);

        return $bytes === false ? null : $bytes;
    }

    /**
     * The IPv4 addresses an IPv6 address carries, as bytes.
     *
     * @param  string  $bytes
     * @return list<string>
     */
    private static function carriedIpv4(string $bytes): array
    {
        if (strlen($bytes) !== 16) {
            return [];
        }

        $carried = [];

        foreach (self::IPV4_CARRIERS as $range => $offsets) {
            if (!self::isWithin($bytes, $range)) {
                continue;
            }

            $carried[] = implode('', array_map(static fn (int $offset): string => $bytes[$offset], $offsets));
        }

        return $carried;
    }

    /**
     * Whether the address is within any of the ranges.
     *
     * @param  string  $bytes
     * @param  list<string>  $ranges
     * @return bool
     */
    private static function isWithinAny(string $bytes, array $ranges): bool
    {
        foreach ($ranges as $range) {
            if (self::isWithin($bytes, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the address is within a range of its own family.
     *
     * @param  string  $bytes
     * @param  string  $range
     * @return bool
     */
    private static function isWithin(string $bytes, string $range): bool
    {
        [$network, $prefix] = explode('/', $range, 2) + [1 => ''];

        $networkBytes = self::bytes($network);

        if ($networkBytes === null || strlen($networkBytes) !== strlen($bytes)) {
            return false;
        }

        $length = (int) $prefix;
        $whole  = intdiv($length, 8);
        $bits   = $length % 8;
        $mask   = (0xFF << (8 - $bits)) & 0xFF;

        return strncmp($bytes, $networkBytes, $whole) === 0
            && ($bits === 0 || (ord($bytes[$whole]) & $mask) === (ord($networkBytes[$whole]) & $mask));
    }
}
