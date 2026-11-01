<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;

/**
 * The default DNS resolver (SSO-3.2, decision D3): the system resolver, through
 * `dns_get_record()` for the name's TXT records.
 *
 * The name is looked up as absolute, with a trailing dot, so the system
 * resolver's search list and `ndots` never put another name in its place: an
 * answer under a search domain is never read as the claimed domain's record.
 *
 * It has no timeout of its own, and PHP cannot interrupt `dns_get_record()`, so
 * a slow resolver holds the request, job or command for as long as the system
 * allows: bind your own `Contracts\DnsResolver` for a bounded deadline, DNSSEC
 * validation or DNS over HTTPS.
 *
 * An answer with no TXT record, which is how PHP reports a name that does not
 * exist too, is `absent`. A lookup that fails (`false`), or answers with a
 * warning, is `lookup_failed`, never `absent`: it proves nothing either way.
 * The failure is logged with the name and PHP's warning, through the package's
 * sanitising logger, and never a record. Of the records found, the first
 * `MAX_RECORDS` of at most `MAX_RECORD_LENGTH` bytes are kept, each record's
 * character-strings joined into one value; an answer whose every TXT record is
 * left out is `absent`.
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

        // Not promoted: `dns_get_record()` stands in when none is given; a test
        // gives its own, so no name is looked up over the network
        ?\Closure $lookup = null,
    ) {
        $this->lookup = $lookup ?? dns_get_record(...);
    }

    /**
     * The TXT records at the name.
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
     * The value of each TXT record of the answer, its character-strings joined,
     * up to `MAX_RECORDS` of at most `MAX_RECORD_LENGTH` bytes.
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
     * The record's value: its `entries` joined, or its `txt` when it has no
     * entries; `null` when it holds neither as strings.
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
