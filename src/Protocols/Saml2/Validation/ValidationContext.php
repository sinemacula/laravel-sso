<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;

/**
 * What one SAML response is judged against (SSO-6.4 to SSO-6.6, SSO-6.9,
 * SSO-6.10): the connection's id and settings, its assertion consumer service
 * and service provider entity id as the endpoint resolver built them, the one
 * instant every time rule reads, the clock skew and the `IssueInstant` maximum
 * age, and the request consumed for the response, or none for the unsolicited
 * profile (SSO-5.8).
 *
 * Every rule of the response validation reads the time from here, so one
 * response is judged at one instant. Each time rule allows the skew one way: an
 * instant that starts a window may be up to the skew after now, and an instant
 * that ends one is passed only once now is the skew beyond it.
 *
 * It is built per validation and kept nowhere (SSO-11.2); the consumed request
 * keeps its own secrets.
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

        /** The connection's assertion consumer service URL, `Destination` and `Recipient` compared with it exactly. */
        public string $assertionConsumerService,

        /** The service provider's entity id, the audience and `SPNameQualifier` compared with it exactly. */
        public string $serviceProviderEntityId,

        /** The instant the response is judged at. */
        public CarbonImmutable $now,

        /** The clock skew every time rule allows, in seconds. */
        public int $skew,

        /** How old an `IssueInstant` may be before the skew, in seconds. */
        public int $issueInstantMaxAge,

        /** The request consumed for the response, or `null` for the unsolicited profile. */
        public ?ConsumedRequest $consumed = null,
    ) {}

    /**
     * Whether the response answers a consumed request, so the solicited
     * profile's rules apply.
     *
     * @return bool
     */
    public function isSolicited(): bool
    {
        return $this->consumed !== null;
    }

    /**
     * The `InResponseTo` every signed and envelope value must carry: the
     * consumed request's SAML request id, or `null`, meaning none, for the
     * unsolicited profile.
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
     * Whether the value is the identity provider's entity id, compared
     * exactly; never when the connection names none.
     *
     * @param  string  $value
     * @return bool
     */
    public function isIdentityProvider(string $value): bool
    {
        return $value === $this->options->idpEntityId;
    }

    /**
     * Whether an instant that starts a window has started: it is not after now
     * plus the skew.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     * @return bool
     */
    public function hasStarted(CarbonImmutable $instant): bool
    {
        return $instant <= $this->now->addSeconds($this->skew);
    }

    /**
     * Whether a window an instant ends has not ended: now is before the instant
     * plus the skew.
     *
     * @param  \Carbon\CarbonImmutable  $notOnOrAfter
     * @return bool
     */
    public function isBefore(CarbonImmutable $notOnOrAfter): bool
    {
        return $this->now < $this->skewed($notOnOrAfter);
    }

    /**
     * Whether an `IssueInstant` is accepted: not after now plus the skew, and
     * no older than the maximum age plus the skew.
     *
     * @param  \Carbon\CarbonImmutable  $issueInstant
     * @return bool
     */
    public function isFresh(CarbonImmutable $issueInstant): bool
    {
        return $this->hasStarted($issueInstant) && $this->now <= $this->freshUntil($issueInstant);
    }

    /**
     * The last moment an `IssueInstant` is accepted: the maximum age plus the
     * skew after it.
     *
     * @param  \Carbon\CarbonImmutable  $issueInstant
     * @return \Carbon\CarbonImmutable
     */
    public function freshUntil(CarbonImmutable $issueInstant): CarbonImmutable
    {
        return $issueInstant->addSeconds($this->issueInstantMaxAge + $this->skew);
    }

    /**
     * The instant with the skew added: when a window it ends is passed.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     * @return \Carbon\CarbonImmutable
     */
    public function skewed(CarbonImmutable $instant): CarbonImmutable
    {
        return $instant->addSeconds($this->skew);
    }
}
