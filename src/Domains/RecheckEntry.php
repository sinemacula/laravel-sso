<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * How the scheduled check of one verified domain ended; safe to log as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecheckEntry implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $domainId
     * @param  string  $connectionId
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome  $outcome
     * @param  ?\Carbon\CarbonImmutable  $lapsesAt
     */
    public function __construct(

        /** The claim's id. */
        public string $domainId,

        /** The id of the connection that claimed the domain. */
        public string $connectionId,

        /** The domain, normalised: lower-case ASCII, no trailing dot. */
        public string $domain,

        /** How its check ended. */
        public RecheckOutcome $outcome,

        /** When it lapses, in UTC; `null` with no record failure pending or when skipped. */
        public ?CarbonImmutable $lapsesAt = null,
    ) {}

    /**
     * The claim's entry after its check; a skipped claim's lapse time is not
     * reported.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome  $outcome
     * @return self
     */
    public static function of(Domain $claim, RecheckOutcome $outcome): self
    {
        $lapsesAt = $outcome === RecheckOutcome::SKIPPED ? null : $claim->lapses_at;

        return new self($claim->id, $claim->connection_id, $claim->domain, $outcome, $lapsesAt);
    }

    /**
     * What `json_encode()` writes: snake_case keys, the time in UTC.
     *
     * @return array{domain_id: string, connection_id: string, domain: string, outcome: string, lapses_at: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'domain_id'     => $this->domainId,
            'connection_id' => $this->connectionId,
            'domain'        => $this->domain,
            'outcome'       => $this->outcome->value,
            'lapses_at'     => $this->lapsesAt?->utc()->format('Y-m-d\TH:i:s\Z'),
        ];
    }
}
