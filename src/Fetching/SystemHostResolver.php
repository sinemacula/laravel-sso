<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use SineMacula\Laravel\Sso\Contracts\HostResolver;

/**
 * The default host resolver: the system resolver, through `dns_get_record()`
 * for the name's A and AAAA records.
 *
 * It has no timeout of its own, so a slow resolver holds the request for as
 * long as the system allows; bind your own `HostResolver` for a bounded
 * deadline, DNSSEC or DNS over HTTPS. A lookup that fails, or answers with a
 * warning, is no address, never an exception: the fetcher reports it as a
 * failed fetch.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SystemHostResolver implements HostResolver
{
    /** @var \Closure(string, int): mixed The DNS lookup, `dns_get_record()` unless a test gave its own. */
    private \Closure $lookup;

    /**
     * Constructor.
     *
     * @param  ?\Closure(string, int): mixed  $lookup
     */
    public function __construct(

        // Not promoted: `dns_get_record()` stands in when none is given; a test
        // gives its own, so no name is resolved over the network
        ?\Closure $lookup = null,
    ) {
        $this->lookup = $lookup ?? dns_get_record(...);
    }

    /**
     * Every A and AAAA address of the host name, `[]` when there is none or the
     * lookup failed.
     *
     * @param  string  $asciiHost
     * @return list<string>
     */
    #[\Override]
    public function addresses(string $asciiHost): array
    {
        /** @var \ArrayObject<int, int> $warnings */
        $warnings = new \ArrayObject;

        set_error_handler(static function (int $severity) use ($warnings): bool {
            $warnings->append($severity);

            return true;
        });

        try {
            $records = ($this->lookup)($asciiHost, DNS_A | DNS_AAAA);
        } finally {
            restore_error_handler();
        }

        return $warnings->count() === 0 && is_array($records) ? self::addressesOf($records) : [];
    }

    /**
     * The `ip` of each A record and the `ipv6` of each AAAA record, once each.
     *
     * @param  array<array-key, mixed>  $records
     * @return list<string>
     */
    private static function addressesOf(array $records): array
    {
        $addresses = [];

        foreach ($records as $record) {
            $address = is_array($record) ? ($record['ip'] ?? $record['ipv6'] ?? null) : null;

            if (!is_string($address)) {
                continue;
            }

            $addresses[$address] = $address;
        }

        return array_values($addresses);
    }
}
