<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;

/**
 * The default DNS resolver, through the system's `dns_get_record()`.
 *
 * PHP cannot interrupt the lookup, so it has no timeout; bind your own
 * `Contracts\DnsResolver` for a deadline.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SystemDnsResolver implements DnsResolver
{
    /** @var int The most TXT records kept from one answer. */
    public const int MAX_RECORDS = 64;

    /** @var int The longest TXT record kept, in bytes. */
    public const int MAX_RECORD_LENGTH = 4096;

    /** @var \Closure(string, int): mixed The DNS lookup, `dns_get_record()` unless a test gave its own. */
    private \Closure $lookup;

    /**
     * Constructor.
     *
     * @param  \Psr\Log\LoggerInterface  $logger
     * @param  ?\Closure(string, int): mixed  $lookup
     */
    public function __construct(

        /** Where a failed lookup is logged: the package's sanitising logger. */
        private LoggerInterface $logger,

        // Not promoted: defaults to `dns_get_record()`; a test gives its own
        ?\Closure $lookup = null,
    ) {
        $this->lookup = $lookup ?? dns_get_record(...);
    }

    /**
     * The TXT records at the name; a failure or warning is `lookup_failed`,
     * never `absent`.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Domains\DnsLookup
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function txt(string $name): DnsLookup
    {
        if ($name === '') {
            throw new \InvalidArgumentException('A DNS lookup needs a name.');
        }

        /** @var \ArrayObject<int, string> $warnings */
        $warnings = new \ArrayObject;

        set_error_handler(static function (int $severity, string $message) use ($warnings): bool {
            $warnings->append(sprintf('%s (severity %d)', $message, $severity));

            return true;
        });

        try {
            // Absolute, so the search list and `ndots` never substitute a name
            $answer = ($this->lookup)($name . '.', DNS_TXT);
        } finally {
            restore_error_handler();
        }

        if ($warnings->count() > 0 || !is_array($answer)) {
            $this->logger->warning('sso.dns.lookup_failed', ['name' => $name, 'error' => $warnings[0] ?? 'no answer']);

            return DnsLookup::lookupFailed();
        }

        $records = self::recordsOf($answer);

        return $records === [] ? DnsLookup::absent() : DnsLookup::found($records);
    }

    /**
     * Each TXT record's value, up to `MAX_RECORDS` within `MAX_RECORD_LENGTH`.
     *
     * @param  array<array-key, mixed>  $answer
     * @return list<string>
     */
    private static function recordsOf(array $answer): array
    {
        $records = [];

        foreach ($answer as $record) {

            $value = is_array($record) && ($record['type'] ?? null) === 'TXT' ? self::valueOf($record) : null;

            if ($value === null || strlen($value) > self::MAX_RECORD_LENGTH) {
                continue;
            }

            $records[] = $value;

            if (count($records) === self::MAX_RECORDS) {
                break;
            }
        }

        return $records;
    }

    /**
     * The record's `entries` joined, else its `txt`; `null` when neither is
     * usable.
     *
     * @param  array<array-key, mixed>  $record
     * @return ?string
     */
    private static function valueOf(array $record): ?string
    {
        $entries = $record['entries'] ?? null;

        if (is_array($entries) && $entries !== [] && array_filter($entries, is_string(...)) === $entries) {
            return implode('', $entries);
        }

        return is_string($record['txt'] ?? null) ? $record['txt'] : null;
    }
}
