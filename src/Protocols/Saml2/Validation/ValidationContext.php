<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;

/**
 * What one SAML response is judged against, at a single instant. Each time rule
 * allows the skew in one direction only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ValidationContext
{
    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  string  $assertionConsumerService
     * @param  string  $serviceProviderEntityId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $skew
     * @param  int  $issueInstantMaxAge
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The connection the response arrived for. */
        public string $connectionId,

        /** The connection's SAML settings. */
        public Saml2Options $options,

        /** The ACS URL `Destination` and `Recipient` must equal. */
        public string $assertionConsumerService,

        /** The SP entity id the audience and `SPNameQualifier` must equal. */
        public string $serviceProviderEntityId,

        /** The instant the response is judged at. */
        public CarbonImmutable $now,

        /** The clock skew every time rule allows, in seconds. */
        public int $skew,

        /** How old an `IssueInstant` may be before the skew, in seconds. */
        public int $issueInstantMaxAge,

        /** The consumed request; `null` for the unsolicited profile. */
        public ?ConsumedRequest $consumed = null,
    ) {}

    /**
     * Whether the solicited profile's rules apply.
     *
     * @return bool
     */
    public function isSolicited(): bool
    {
        return $this->consumed !== null;
    }

    /**
     * The `InResponseTo` every value must carry; `null` means none may.
     *
     * @return ?string
     */
    public function expectedRequestId(): ?string
    {
        return $this->consumed?->samlRequestId;
    }

    /**
     * When the consumed request started, for a `reauthenticate` request only.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    public function reauthenticationStart(): ?CarbonImmutable
    {
        $consumed = $this->consumed;

        if ($consumed === null || $consumed->purpose !== Purpose::REAUTHENTICATE) {
            return null;
        }

        return $consumed->startedAt;
    }

    /**
     * Whether the value is exactly the identity provider's entity id.
     *
     * @param  string  $value
     * @return bool
     */
    public function isIdentityProvider(string $value): bool
    {
        return $value === $this->options->idpEntityId;
    }

    /**
     * Whether a window's start is not after now plus the skew.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     * @return bool
     */
    public function hasStarted(CarbonImmutable $instant): bool
    {
        return $instant <= $this->now->addSeconds($this->skew);
    }

    /**
     * Whether now is before a window's end plus the skew.
     *
     * @param  \Carbon\CarbonImmutable  $notOnOrAfter
     * @return bool
     */
    public function isBefore(CarbonImmutable $notOnOrAfter): bool
    {
        return $this->now < $this->skewed($notOnOrAfter);
    }

    /**
     * Whether an `IssueInstant` is neither in the future nor too old, each with
     * the skew.
     *
     * @param  \Carbon\CarbonImmutable  $issueInstant
     * @return bool
     */
    public function isFresh(CarbonImmutable $issueInstant): bool
    {
        return $this->hasStarted($issueInstant) && $this->now <= $this->freshUntil($issueInstant);
    }

    /**
     * The last moment an `IssueInstant` is accepted.
     *
     * @param  \Carbon\CarbonImmutable  $issueInstant
     * @return \Carbon\CarbonImmutable
     */
    public function freshUntil(CarbonImmutable $issueInstant): CarbonImmutable
    {
        return $issueInstant->addSeconds($this->issueInstantMaxAge + $this->skew);
    }

    /**
     * The instant plus the skew: when a window it ends is passed.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     * @return \Carbon\CarbonImmutable
     */
    public function skewed(CarbonImmutable $instant): CarbonImmutable
    {
        return $instant->addSeconds($this->skew);
    }
}
