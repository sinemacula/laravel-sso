<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * What a reservation is made under and bound to (SSO-8.8): the request it was
 * made for, the linking email, the organisation claim's accepted value, the
 * domain claim locked, with its verification generation, the linking policy
 * version the evidence was accepted under, and when it expires.
 *
 * It holds the email only to digest it and the organisation only to store it,
 * each in a `\SensitiveParameterValue` behind its accessor, so a dump shows
 * ids, `json_encode()` writes both `[redacted]`, and it refuses to be
 * serialised or unserialised. It keeps the domain claim's id and generation and
 * not the claim.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReservationTerms implements \JsonSerializable
{
    /** @var string The domain claim's id. */
    public string $domainId;

    /** @var int The domain claim's verification generation. */
    public int $domainGeneration;

    /** @var \SensitiveParameterValue The linking email, exactly as asserted. */
    private \SensitiveParameterValue $email;

    /** @var \SensitiveParameterValue The organisation claim's accepted value, if the issuer is shared. */
    private \SensitiveParameterValue $organization;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @param  string  $email
     * @param  ?string  $organization
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  int  $linkingVersion
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** The request the reservation was made for. */
        public RequestReference $reference,

        // The linking email, exactly as asserted; held wrapped
        #[\SensitiveParameter]
        string $email,

        // The organisation claim's accepted value, if the issuer is shared; held
        // wrapped
        #[\SensitiveParameter]
        ?string $organization,

        // The domain claim, locked; its id and generation are kept
        Domain $domain,

        /** The linking policy version the evidence was accepted under. */
        public int $linkingVersion,

        /** When the reservation expires. */
        public CarbonImmutable $expiresAt,
    ) {
        $this->email            = new \SensitiveParameterValue($email);
        $this->organization     = new \SensitiveParameterValue($organization);
        $this->domainId         = $domain->id;
        $this->domainGeneration = $domain->verification_generation;
    }

    /**
     * What a dump shows: the request and the domain claim, never the email or
     * the organisation.
     *
     * @return array<string, int|string>
     */
    public function __debugInfo(): array
    {
        return ['request_reference' => $this->reference->value, 'domain_id' => $this->domainId, 'linking_version' => $this->linkingVersion];
    }

    /**
     * Refuse to be serialised: it holds the email.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A reservation\'s terms cannot be serialised.');
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
        throw new \LogicException('A reservation\'s terms cannot be unserialised.');
    }

    /**
     * What `json_encode()` writes: the ids, with the email and the organisation
     * redacted.
     *
     * @return array<string, int|string>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [...$this->__debugInfo(), 'email' => '[redacted]', 'organization' => '[redacted]'];
    }

    /**
     * The linking email, exactly as asserted.
     *
     * @return string
     */
    public function email(): string
    {
        /** @var string */
        return $this->email->getValue();
    }

    /**
     * The organisation claim's accepted value, if the issuer is shared.
     *
     * @return ?string
     */
    public function organization(): ?string
    {
        /** @var ?string */
        return $this->organization->getValue();
    }
}
