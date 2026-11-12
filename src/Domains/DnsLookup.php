<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use SineMacula\Laravel\Sso\Domains\Enums\DnsLookupStatus;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * What a TXT lookup through the `Contracts\DnsResolver` answered.
 *
 * The records are attacker-supplied, so they are held wrapped and never dumped,
 * encoded or serialised.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DnsLookup implements \JsonSerializable
{
    /** @var \SensitiveParameterValue The records found, each a `string`, none unless found. */
    private \SensitiveParameterValue $records;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\DnsLookupStatus  $status
     * @param  list<string>  $records
     */
    private function __construct(

        /** What the lookup answered. */
        public DnsLookupStatus $status,

        // Not promoted: held wrapped, so no dump, export or array cast shows it
        #[\SensitiveParameter]
        array $records = [],
    ) {
        $this->records = new \SensitiveParameterValue($records);
    }

    /**
     * What a dump shows: the status and how many records, never a record.
     *
     * @return array<string, int|string>
     */
    public function __debugInfo(): array
    {
        return ['status' => $this->status->value, 'records' => count($this->records()) . ' [redacted]'];
    }

    /**
     * Refuse to be serialised: a lookup lives only for the check that made it.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A DNS lookup cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A DNS lookup cannot be unserialised.');
    }

    /**
     * The name has these TXT records, each its character-strings joined.
     *
     * @param  list<string>  $records
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function found(#[\SensitiveParameter] array $records): self
    {
        if ($records === []) {
            throw new \InvalidArgumentException('A found lookup holds at least one record.');
        }

        return new self(DnsLookupStatus::FOUND, array_map(static fn (string $record): string => $record, $records));
    }

    /**
     * The name has no TXT record, or does not exist.
     *
     * @return self
     */
    public static function absent(): self
    {
        return new self(DnsLookupStatus::ABSENT);
    }

    /**
     * The resolver could not answer.
     *
     * @return self
     */
    public static function lookupFailed(): self
    {
        return new self(DnsLookupStatus::LOOKUP_FAILED);
    }

    /**
     * Whether the name has TXT records.
     *
     * @return bool
     */
    public function isFound(): bool
    {
        return $this->status === DnsLookupStatus::FOUND;
    }

    /**
     * Whether the name has no TXT record.
     *
     * @return bool
     */
    public function isAbsent(): bool
    {
        return $this->status === DnsLookupStatus::ABSENT;
    }

    /**
     * Whether the resolver could not answer.
     *
     * @return bool
     */
    public function isLookupFailed(): bool
    {
        return $this->status === DnsLookupStatus::LOOKUP_FAILED;
    }

    /**
     * The records found, raw as the DNS gave them; none unless found.
     *
     * @return list<string>
     */
    public function records(): array
    {
        /** @var list<string> */
        return $this->records->getValue();
    }

    /**
     * Whether a record is exactly the value, in constant time; never for an
     * empty value.
     *
     * @param  string  $value
     * @return bool
     */
    public function contains(#[\SensitiveParameter] string $value): bool
    {
        $matched = false;

        foreach ($this->records() as $record) {
            $matched = ConstantTime::equals($value, $record) || $matched;
        }

        return $value !== '' && $matched;
    }

    /**
     * What `json_encode()` writes: the status, never a record.
     *
     * @return array{status: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['status' => $this->status->value];
    }
}
