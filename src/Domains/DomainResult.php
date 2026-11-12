<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a domain operation ended; a refusal is returned, never thrown, and wrote
 * nothing.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DomainResult implements \JsonSerializable
{
    /** @var list<\SineMacula\Laravel\Sso\Events\Enums\FailureReason> The refusal reasons, rate limiting aside. */
    private const array REFUSALS = [
        FailureReason::FRESHNESS_REQUIRED,
        FailureReason::CONNECTION_NOT_FOUND,
        FailureReason::DOMAIN_NOT_FOUND,
        FailureReason::DOMAIN_UNAVAILABLE,
        FailureReason::DOMAIN_CLAIM_EXPIRED,
        FailureReason::DOMAIN_RECORD_NOT_FOUND,
        FailureReason::DOMAIN_LOOKUP_FAILED,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\DomainStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Domains\DomainSummary  $domain
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** How the operation ended. */
        public DomainStatus $status,

        /** The domain, for a success only. */
        public ?DomainSummary $domain = null,

        /** Why it was refused, for `refused` and `invalid` only. */
        public ?FailureReason $reason = null,

        /** Every violation found, for `invalid` only. */
        public array $violations = [],

        /** Seconds until it may be tried again, when rate limited only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * The domain was claimed, pending.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainSummary  $domain
     * @return self
     */
    public static function claimed(DomainSummary $domain): self
    {
        return new self(DomainStatus::CLAIMED, $domain);
    }

    /**
     * The domain was verified.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainSummary  $domain
     * @return self
     */
    public static function verified(DomainSummary $domain): self
    {
        return new self(DomainStatus::VERIFIED, $domain);
    }

    /**
     * The domain was verified already; nothing was looked up or written.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainSummary  $domain
     * @return self
     */
    public static function unchanged(DomainSummary $domain): self
    {
        return new self(DomainStatus::UNCHANGED, $domain);
    }

    /**
     * The claim was removed; the summary is as it was before.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainSummary  $domain
     * @return self
     */
    public static function removed(DomainSummary $domain): self
    {
        return new self(DomainStatus::REMOVED, $domain);
    }

    /**
     * The operation was refused for the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason): self
    {
        if (!in_array($reason, self::REFUSALS, true)) {
            throw new \InvalidArgumentException(sprintf('A domain operation is not refused for [%s].', $reason->value));
        }

        return new self(DomainStatus::REFUSED, reason: $reason);
    }

    /**
     * The connection has used up its domain checks for now.
     *
     * @param  int  $retryAfter
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function rateLimited(int $retryAfter): self
    {
        if ($retryAfter < 1) {
            throw new \InvalidArgumentException('A rate limited domain check waits at least one second.');
        }

        return new self(DomainStatus::REFUSED, reason: FailureReason::RATE_LIMITED, retryAfter: $retryAfter);
    }

    /**
     * The domain given was refused, for each of these violations.
     *
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function invalid(array $violations): self
    {
        if ($violations === []) {
            throw new \InvalidArgumentException('An invalid domain names at least one violation.');
        }

        return new self(DomainStatus::INVALID, reason: FailureReason::SETTINGS_INVALID, violations: $violations);
    }

    /**
     * Whether the operation succeeded: claimed, verified, unchanged or removed.
     *
     * @return bool
     */
    public function isSucceeded(): bool
    {
        return $this->status->isSucceeded();
    }

    /**
     * Whether the operation wrote something: claimed, verified or removed.
     *
     * @return bool
     */
    public function isChanged(): bool
    {
        return $this->isSucceeded() && $this->status !== DomainStatus::UNCHANGED;
    }

    /**
     * Whether the operation was refused, with a reason, rate limited included.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status === DomainStatus::REFUSED;
    }

    /**
     * Whether the connection has used up its domain checks for now.
     *
     * @return bool
     */
    public function isRateLimited(): bool
    {
        return $this->reason === FailureReason::RATE_LIMITED;
    }

    /**
     * Whether the domain given was refused, with its violations.
     *
     * @return bool
     */
    public function isInvalid(): bool
    {
        return $this->status === DomainStatus::INVALID;
    }

    /**
     * The result with snake_case keys; never the domain's token.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'status'      => $this->status->value,
            'domain'      => $this->domain?->jsonSerialize(),
            'reason'      => $this->reason?->value,
            'violations'  => array_map(static fn (SettingViolation $violation): array => $violation->jsonSerialize(), $this->violations),
            'retry_after' => $this->retryAfter,
        ];
    }
}
