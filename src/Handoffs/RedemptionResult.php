<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\Enums\RedemptionStatus;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * How redeeming a handoff code with the package's own redemption helper ended
 * (SSO-9.2, SSO-9.9, SSO-11.8), the value the application's redemption endpoint
 * answers from:
 *
 * - redeemed: the code was consumed now and every check passed; it carries the
 *   verified result, the identity its link resolved to at completion (and still
 *   resolves to), the identity a `link` or `reauthenticate` flow was started
 *   for, the session a `reauthenticate` flow was started on, the enforcement
 *   version the completion checked, the latest end of the application's session
 *   the provider's deadline sets (SSO-9.10), the link that established it, the
 *   evidence the evidence contract accepted, and whether it was admitted:
 *   redeemed inside the caller's transaction, so its session write commits with
 *   it. A
 *   result not admitted must never lead to a session;
 * - refused: for the reason given, the first check that refused it; a code
 *   consumed before the refusal stays consumed;
 * - rate limited: the redemption limit for the client's IP address is full,
 *   with the seconds until it may be tried again.
 *
 * Its outcome is its `status` (`Handoffs\Enums\RedemptionStatus`); a refused or
 * rate limited one names its `reason` too, `rate_limited` when throttled. A
 * database error is never one of these: it propagates as a server error
 * (SSO-11.4).
 *
 * It holds the verified result, which carries personal data (the subject and
 * the mapped attributes), so a dump and `json_encode()` show only the outcome,
 * the purpose, the connection and the request's public reference, never the
 * result's attributes, and it refuses to be serialised or unserialised: it
 * lives only for the request that redeemed the code. The result itself is
 * serialisable, as SSO-8.1 requires, for an application that keeps it.
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
     */
    private function __construct(

        /** How the redemption ended. */
        public RedemptionStatus $status,

        /** Why the code was not redeemed, `rate_limited` included; none when it was. */
        public ?FailureReason $reason = null,

        /** Seconds, at least 1, until it may be tried again, for a rate limited one. */
        public ?int $retryAfter = null,

        /** The verified result the code carried, for a redeemed one. */
        public ?VerifiedResult $result = null,

        /** The identity the result's link resolved to at completion and still resolves to, if any. */
        public ?IdentityReference $linkedIdentity = null,

        /** The identity a `link` or `reauthenticate` flow was started for. */
        public ?IdentityReference $identity = null,

        /** The session a `reauthenticate` flow was started on. */
        public ?string $sessionId = null,

        /** The enforcement version the completion checked (SSO-4.6, SSO-9.10). */
        public ?string $enforcementVersion = null,

        /** The latest end of the application's session the provider's deadline sets. */
        public ?CarbonImmutable $sessionNotAfter = null,

        /** The link the identity resolved through, which a session binds. */
        public ?string $linkId = null,

        /** What the evidence contract accepted of the result's own assertion. */
        public ?AcceptedEvidence $evidence = null,

        /** Whether it was redeemed inside the caller's transaction. */
        public bool $admitted = false,
    ) {}

    /**
     * What a dump shows: the outcome, never the result's subject or attributes.
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
     * Whether the code was redeemed inside the caller's transaction, so what
     * the caller writes with it commits with its consumption (decision D5).
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
     * What `json_encode()` writes: the outcome, as a dump shows it.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->summary();
    }

    /**
     * The outcome, the purpose, the connection and the request's public
     * reference: what may be shown of the redemption.
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
