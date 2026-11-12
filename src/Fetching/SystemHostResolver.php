<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use SineMacula\Laravel\Sso\Contracts\HostResolver;

/**
 * The default host resolver, through `dns_get_record()`. It has no timeout and
 * PHP cannot interrupt it; bind your own `HostResolver` for a bounded lookup.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SystemHostResolver implements HostResolver
{
    /** @var \Closure(string, int): mixed The DNS lookup, replaceable by tests. */
    private \Closure $lookup;

    /**
     * Constructor.
     *
     * @param  ?\Closure(string, int): mixed  $lookup
     */
    public function __construct(

        // Not promoted: defaults to `dns_get_record()` when none is given
        ?\Closure $lookup = null,
    ) {
        $this->lookup = $lookup ?? dns_get_record(...);
    }

    /**
     * Every A and AAAA address of the host, or `[]` when the lookup fails or
     * warns.
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
     * The distinct `ip` and `ipv6` values of the records.
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
