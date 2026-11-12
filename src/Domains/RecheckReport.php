<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;

/**
 * What one run of the scheduled domain recheck did, claim by claim.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecheckReport implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Sso\Domains\RecheckEntry>  $entries
     */
    public function __construct(

        /** Every claim checked, in the order it was checked. */
        public array $entries = [],
    ) {}

    /**
     * How many claims ended with the outcome.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome  $outcome
     * @return int
     */
    public function count(RecheckOutcome $outcome): int
    {
        return count(array_filter($this->entries, static fn (RecheckEntry $entry): bool => $entry->outcome === $outcome));
    }

    /**
     * Whether the resolver could not answer for at least one claim.
     *
     * @return bool
     */
    public function hasLookupFailures(): bool
    {
        return $this->count(RecheckOutcome::LOOKUP_FAILED) > 0;
    }

    /**
     * Whether the resolver threw, rather than answered, for at least one claim.
     *
     * @return bool
     */
    public function hasResolverThrows(): bool
    {
        return $this->count(RecheckOutcome::RESOLVER_THREW) > 0;
    }

    /**
     * What `json_encode()` writes: every entry, in order, and each outcome's
     * count.
     *
     * @return array{entries: list<array{domain_id: string, connection_id: string, domain: string, outcome: string, lapses_at: ?string}>, counts: array<string, int>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        $counts = [];

        foreach (RecheckOutcome::cases() as $outcome) {
            $counts[$outcome->value] = $this->count($outcome);
        }

        return [
            'entries' => array_map(static fn (RecheckEntry $entry): array => $entry->jsonSerialize(), $this->entries),
            'counts'  => $counts,
        ];
    }
}
