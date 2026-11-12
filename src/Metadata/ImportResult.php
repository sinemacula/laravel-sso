<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How an import of an identity provider's SAML metadata ended: proposed,
 * refused or rate limited.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ImportResult
{
    /** @var list<\SineMacula\Laravel\Sso\Events\Enums\FailureReason> The reasons an import is refused for. */
    public const array REFUSALS = [
        FailureReason::PROTOCOL_UNAVAILABLE,
        FailureReason::CONNECTION_NOT_FOUND,
        FailureReason::FETCH_REFUSED,
        FailureReason::FETCH_FAILED,
        FailureReason::METADATA_INVALID,
        FailureReason::METADATA_SIGNATURE_INVALID,
        FailureReason::METADATA_ENTITY_NOT_FOUND,
        FailureReason::METADATA_EXPIRED,
    ];

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Metadata\ProposedSettings  $proposed
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?string  $detail
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** The settings the metadata proposes, for a proposed import. */
        public ?ProposedSettings $proposed = null,

        /** Why it was refused or limited, for one that was. */
        public ?FailureReason $reason = null,

        /** The rule that refused the metadata, such as `schema`, never a value of it. */
        public ?string $detail = null,

        /** Seconds, at least 1, until it may be tried again, for a rate limited one. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * The metadata was read and proposes the settings.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\ProposedSettings  $proposed
     * @return self
     */
    public static function proposed(ProposedSettings $proposed): self
    {
        return new self($proposed);
    }

    /**
     * The import was refused for the reason, by the rule named when the
     * metadata was refused.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?string  $detail
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason, ?string $detail = null): self
    {
        if (!in_array($reason, self::REFUSALS, true)) {
            throw new \InvalidArgumentException(sprintf('An import is not refused for [%s].', $reason->value));
        }

        return new self(reason: $reason, detail: $detail);
    }

    /**
     * Too many imports of the connection were tried.
     *
     * @param  int  $retryAfter
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function rateLimited(int $retryAfter): self
    {
        if ($retryAfter < 1) {
            throw new \InvalidArgumentException('A rate limited import may be tried again after at least 1 second.');
        }

        return new self(reason: FailureReason::RATE_LIMITED, retryAfter: $retryAfter);
    }

    /**
     * Whether the metadata was read and proposes settings.
     *
     * @return bool
     */
    public function isProposed(): bool
    {
        return $this->proposed !== null;
    }

    /**
     * Whether the import was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->proposed === null && $this->reason !== FailureReason::RATE_LIMITED;
    }

    /**
     * Whether too many imports of the connection were tried.
     *
     * @return bool
     */
    public function isRateLimited(): bool
    {
        return $this->reason === FailureReason::RATE_LIMITED;
    }
}
