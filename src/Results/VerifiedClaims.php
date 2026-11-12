<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

/**
 * What a protocol driver verified in a response, built only from its verified
 * element.
 *
 * It holds raw provider values, so it lives only for the completion: dumps and
 * JSON omit them, and it refuses serialisation.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class VerifiedClaims implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $nameIdFormat
     * @param  array<string, mixed>  $attributes
     * @param  \SineMacula\Laravel\Sso\Results\AuthenticationContext  $authenticationContext
     * @param  ?\SineMacula\Laravel\Sso\Results\LinkingEmail  $linkingEmail
     * @param  ?\SineMacula\Laravel\Sso\Results\AssertedEmail  $assertedEmail
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity provider's identifier: the SAML `Issuer`, the OIDC `iss`. */
        public string $issuer,

        /** The person's stable identifier at the provider, exactly as received. */
        public string $subject,

        /** The SAML `NameID` format; `null` for OIDC or an attribute subject. */
        public ?string $nameIdFormat,

        /** The raw attributes or claims the mapping reads from, by name. */
        public array $attributes,

        /** The provider's authentication context. */
        public AuthenticationContext $authenticationContext,

        /** The protocol-asserted email, where domain linking applies. */
        public ?LinkingEmail $linkingEmail = null,

        /** The email and `email_verified` an OIDC provider asserted, from one source. */
        public ?AssertedEmail $assertedEmail = null,
    ) {
        StoredValues::assertText('issuer', $issuer, VerifiedResult::MAX_ISSUER_LENGTH);
        StoredValues::assertText('subject', $subject, VerifiedResult::MAX_SUBJECT_LENGTH);
        StoredValues::assertOptionalText('NameID format', $nameIdFormat, VerifiedResult::MAX_NAME_ID_FORMAT_LENGTH);
    }

    /**
     * A dump without the subject or attribute values.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'issuer'         => $this->issuer,
            'subject'        => '[redacted]',
            'name_id_format' => $this->nameIdFormat,
            'attributes'     => array_keys($this->attributes),
        ];
    }

    /**
     * Refuse to be serialised.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('Verified claims cannot be serialised.');
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
        throw new \LogicException('Verified claims cannot be unserialised.');
    }

    /**
     * JSON without the subject or attribute values; attributes show their type.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        $json = [
            'issuer'                 => $this->issuer,
            'subject'                => StoredValues::REDACTED,
            'name_id_format'         => $this->nameIdFormat,
            'attributes'             => array_map(get_debug_type(...), $this->attributes),
            'authentication_context' => $this->authenticationContext->jsonSerialize(),
            'linking_email'          => $this->linkingEmail?->jsonSerialize(),
        ];

        return $this->assertedEmail === null ? $json : [...$json, 'asserted_email' => $this->assertedEmail->jsonSerialize()];
    }
}
