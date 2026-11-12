<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\Enums\RedemptionStatus;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Sessions\Provenance;

/**
 * How a handoff redemption ended.
 *
 * Only a result that isAdmitted() may lead to a session.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RedemptionResult implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RedemptionStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @param  ?\SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @param  ?string  $enforcementVersion
     * @param  ?\Carbon\CarbonImmutable  $sessionNotAfter
     * @param  ?string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @param  bool  $admitted
     * @param  ?\SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     */
    private function __construct(

        /** How the redemption ended. */
        public RedemptionStatus $status,

        /** Why the code was not redeemed, `rate_limited` included. */
        public ?FailureReason $reason = null,

        /** Seconds, at least 1, until a rate limited redemption may be retried. */
        public ?int $retryAfter = null,

        /** The verified result the code carried, for a redeemed one. */
        public ?VerifiedResult $result = null,

        /** The identity the result's link resolved to, then and now. */
        public ?IdentityReference $linkedIdentity = null,

        /** The identity a `link` or `reauthenticate` flow was started for. */
        public ?IdentityReference $identity = null,

        /** The session a `reauthenticate` flow was started on. */
        public ?string $sessionId = null,

        /** The enforcement version judged under the redemption's locks. */
        public ?string $enforcementVersion = null,

        /** The session's latest end, set by the provider's deadline. */
        public ?CarbonImmutable $sessionNotAfter = null,

        /** The link the identity resolved through, which a session binds. */
        public ?string $linkId = null,

        /** What the evidence contract accepted of the result's own assertion. */
        public ?AcceptedEvidence $evidence = null,

        /** Whether it was redeemed inside the caller's transaction. */
        public bool $admitted = false,

        /** The session provenance captured from an admitted `sign_in`; none otherwise. */
        public ?Provenance $provenance = null,
    ) {}

    /**
     * Dump the outcome only, never the result's subject or attributes.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return $this->summary();
    }

    /**
     * Refuse to be serialised: it holds the verified result.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A redemption result cannot be serialised.');
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
        throw new \LogicException('A redemption result cannot be unserialised.');
    }

    /**
     * The code was consumed now and every check passed.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @param  ?string  $enforcementVersion
     * @param  ?\Carbon\CarbonImmutable  $sessionNotAfter
     * @param  ?string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @param  bool  $admitted
     * @param  ?\SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return self
     *
     * @SuppressWarnings("php:S107")
     */
    public static function redeemed(
        VerifiedResult $result,
        ?IdentityReference $linkedIdentity = null,
        ?IdentityReference $identity = null,
        ?string $sessionId = null,
        ?string $enforcementVersion = null,
        ?CarbonImmutable $sessionNotAfter = null,
        ?string $linkId = null,
        ?AcceptedEvidence $evidence = null,
        bool $admitted = false,
        ?Provenance $provenance = null,
    ): self {
        return new self(
            RedemptionStatus::REDEEMED,
            result: $result,
            linkedIdentity: $linkedIdentity,
            identity: $identity,
            sessionId: $sessionId,
            enforcementVersion: $enforcementVersion,
            sessionNotAfter: $sessionNotAfter,
            linkId: $linkId,
            evidence: $evidence,
            admitted: $admitted,
            provenance: $provenance,
        );
    }

    /**
     * The redemption was refused, for any reason but throttling.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason): self
    {
        if ($reason === FailureReason::RATE_LIMITED) {
            throw new \InvalidArgumentException('A rate limited redemption is answered by rateLimited(), with its wait.');
        }

        return new self(RedemptionStatus::REFUSED, $reason);
    }

    /**
     * The redemption limit is full for the seconds given.
     *
     * @param  int  $retryAfter
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function rateLimited(int $retryAfter): self
    {
        if ($retryAfter < 1) {
            throw new \InvalidArgumentException('A rate limited redemption waits at least one second.');
        }

        return new self(RedemptionStatus::RATE_LIMITED, FailureReason::RATE_LIMITED, $retryAfter);
    }

    /**
     * Whether the code was redeemed.
     *
     * @return bool
     */
    public function isRedeemed(): bool
    {
        return $this->status === RedemptionStatus::REDEEMED;
    }

    /**
     * Whether the code was redeemed inside the caller's transaction, so a
     * session written with it commits with the consumption.
     *
     * @return bool
     */
    public function isAdmitted(): bool
    {
        return $this->isRedeemed() && $this->admitted;
    }

    /**
     * Whether the redemption was refused for a reason other than throttling.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status === RedemptionStatus::REFUSED;
    }

    /**
     * Whether the redemption was refused by a full limit.
     *
     * @return bool
     */
    public function isRateLimited(): bool
    {
        return $this->status === RedemptionStatus::RATE_LIMITED;
    }

    /**
     * Encode the outcome only, as a dump shows it.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->summary();
    }

    /**
     * What may be shown of the redemption.
     *
     * @return array<string, mixed>
     */
    private function summary(): array
    {
        return [
            'status'            => $this->status->value,
            'reason'            => $this->reason?->value,
            'retry_after'       => $this->retryAfter,
            'purpose'           => $this->result?->purpose->value,
            'connection_id'     => $this->result?->connectionId,
            'request_reference' => $this->result?->requestReference->value,
        ];
    }
}
