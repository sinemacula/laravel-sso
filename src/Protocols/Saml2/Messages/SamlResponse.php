<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile;

/**
 * A SAML `Response` the SAML adapter parsed and verified (SSO-6.1 to SSO-6.3,
 * SSO-6.11): its envelope (`ID`, `Issuer`, `IssueInstant`, `Destination`,
 * `InResponseTo` and status), whether the envelope's own signature was
 * verified, the validation profile it falls under, and its one assertion, if
 * the profile reads one.
 *
 * The envelope's fields come from the verified response when it is signed, and
 * from the parsed, unverified one otherwise (`isSigned()`), so identity and
 * correlation are taken only from signed content: the assertion's fields, or an
 * envelope that is itself signed. The adapter verified every signature present
 * before answering; nothing here is a judgement of issuer, audience, time or
 * subject, which the response validation makes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SamlResponse implements \JsonSerializable
{
    use HoldsProviderValues;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile  $profile
     * @param  string  $id
     * @param  \Carbon\CarbonImmutable  $issueInstant
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlStatus  $status
     * @param  array{issuer?: ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId, destination?: ?string, in_response_to?: ?string}  $envelope
     * @param  bool  $signed
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     */
    public function __construct(
        // The profile the response falls under
        ValidationProfile $profile,
        // The response's identifier
        string $id,
        // The instant the response was issued
        CarbonImmutable $issueInstant,
        // The status the response reports
        SamlStatus $status,
        // The issuer, destination and request answered, each when present
        array $envelope = [],
        // Whether the response's own signature was verified
        bool $signed = false,
        // The one assertion, when the profile reads it
        ?SamlAssertion $assertion = null,
    ) {
        $this->hold([
            'profile'        => $profile,
            'id'             => $id,
            'issue_instant'  => $issueInstant,
            'status'         => $status,
            'issuer'         => $envelope['issuer']         ?? null,
            'destination'    => $envelope['destination']    ?? null,
            'in_response_to' => $envelope['in_response_to'] ?? null,
            'signed'         => $signed,
            'assertion'      => $assertion,
        ]);
    }

    /**
     * The profile the response falls under.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile
     */
    public function profile(): ValidationProfile
    {
        /** @var \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile */
        return $this->held('profile');
    }

    /**
     * The `ID` attribute.
     *
     * @return string
     */
    public function id(): string
    {
        /** @var string */
        return $this->held('id');
    }

    /**
     * The `IssueInstant` attribute.
     *
     * @return \Carbon\CarbonImmutable
     */
    public function issueInstant(): CarbonImmutable
    {
        /** @var \Carbon\CarbonImmutable */
        return $this->held('issue_instant');
    }

    /**
     * The `Status`.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlStatus
     */
    public function status(): SamlStatus
    {
        /** @var \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlStatus */
        return $this->held('status');
    }

    /**
     * The envelope's `Issuer`, or `null` when absent.
     *
     * @return ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId
     */
    public function issuer(): ?NameId
    {
        /** @var ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId */
        return $this->held('issuer');
    }

    /**
     * The `Destination` attribute, or `null` when absent.
     *
     * @return ?string
     */
    public function destination(): ?string
    {
        /** @var ?string */
        return $this->held('destination');
    }

    /**
     * The envelope's `InResponseTo`, or `null` when absent.
     *
     * @return ?string
     */
    public function inResponseTo(): ?string
    {
        /** @var ?string */
        return $this->held('in_response_to');
    }

    /**
     * Whether the response's own signature was verified, so the envelope's
     * fields are signed content.
     *
     * @return bool
     */
    public function isSigned(): bool
    {
        return $this->held('signed') === true;
    }

    /**
     * The one assertion, or `null` when the profile reads none.
     *
     * @return ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    public function assertion(): ?SamlAssertion
    {
        /** @var ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion */
        return $this->held('assertion');
    }
}
