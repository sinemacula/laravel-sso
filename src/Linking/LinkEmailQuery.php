<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

/**
 * What the link email contract is asked to match (SSO-8.8): the connection's
 * tenant, the email exactly as the protocol asserted it, unchanged, and its
 * domain canonicalised as SSO-3.1 compares one
 * (`Domains\DomainName::normalize()`: lower case, IDNA to ASCII, no trailing
 * dot). Lower-casing alone would miss part of that rule, and nothing here
 * touches the local part.
 *
 * The email is held in a `\SensitiveParameterValue` behind `email()`: a dump
 * shows `[redacted]`, `json_encode()` writes `[redacted]`, and it refuses to be
 * serialised or unserialised.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkEmailQuery implements \JsonSerializable
{
    /** @var \SensitiveParameterValue The email, exactly as asserted. */
    private \SensitiveParameterValue $email;

    /**
     * Constructor.
     *
     * @param  string  $tenantId
     * @param  string  $email
     * @param  string  $domain
     */
    public function __construct(

        /** The connection's tenant. */
        public string $tenantId,

        // The email, exactly as asserted; held wrapped
        #[\SensitiveParameter]
        string $email,

        /** The email's domain, canonicalised. */
        public string $domain,
    ) {
        $this->email = new \SensitiveParameterValue($email);
    }

    /**
     * What a dump shows: the tenant and the domain, never the email.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
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
        throw new \LogicException('A link email query cannot be serialised.');
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
        throw new \LogicException('A link email query cannot be unserialised.');
    }

    /**
     * The email, exactly as asserted.
     *
     * @return string
     */
    public function email(): string
    {
        /** @var string */
        return $this->email->getValue();
    }

    /**
     * What `json_encode()` writes: the tenant, the domain and a redacted email.
     *
     * @return array<string, string>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['tenant_id' => $this->tenantId, 'email' => '[redacted]', 'domain' => $this->domain];
    }
}
