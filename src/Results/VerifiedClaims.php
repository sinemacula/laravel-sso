<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

/**
 * What a protocol driver verified in an identity provider's response, once
 * every check of SSO-6 or SSO-7 passed (SSO-8.1): the issuer, the subject and,
 * for a SAML `NameID`, its format; the raw attributes or claims the
 * connection's attribute mapping reads from, by the name the provider gave
 * them; the provider's authentication context; where linking by a verified
 * domain applies, the linking email the protocol asserted; and, for OIDC, the
 * email the provider asserted with its `email_verified`, whichever its value.
 *
 * Only a driver builds it, and only from its verified element (SSO-6.3); the
 * completion pipeline maps the attributes and adds the connection, tenant,
 * protocol, application, purpose and request reference to make the
 * `VerifiedResult`. It holds no assertion, token or secret, but it holds raw
 * provider values, so it lives only for the completion that verified it: a dump
 * shows the names of the attributes and never their values; `json_encode()`,
 * and a logger's normaliser that falls back to it, write the issuer, the NameID
 * format, each attribute's name with its kind and the redacted forms of the
 * authentication context, the linking email and, when there is one, the
 * asserted email, never the subject or a value the provider asserted; and it
 * refuses to be serialised or unserialised.
 *
 * The issuer and subject are 1 to 1024 bytes and kept exactly as received,
 * never trimmed or normalised (SSO-6.9); a NameID format is 1 to 255 bytes. A
 * driver refuses a response that breaks these as a value before building it: a
 * value that reaches the constructor broken is the driver's mistake
 * (`InvalidArgumentException`).
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

        /** The SAML `NameID` format the subject was asserted in; `null` for OIDC or an attribute subject. */
        public ?string $nameIdFormat,

        /** The raw attributes or claims the mapping reads from, by name. */
        public array $attributes,

        /** The provider's authentication context. */
        public AuthenticationContext $authenticationContext,

        /** The linking email the protocol asserted, where linking by a verified domain applies. */
        public ?LinkingEmail $linkingEmail = null,

        /** The email and `email_verified` an OIDC provider asserted, from one source. */
        public ?AssertedEmail $assertedEmail = null,
    ) {
        StoredValues::assertText('issuer', $issuer, VerifiedResult::MAX_ISSUER_LENGTH);
        StoredValues::assertText('subject', $subject, VerifiedResult::MAX_SUBJECT_LENGTH);
        StoredValues::assertOptionalText('NameID format', $nameIdFormat, VerifiedResult::MAX_NAME_ID_FORMAT_LENGTH);
    }

    /**
     * What a dump shows: the issuer, the NameID format and the names of the
     * attributes, never the subject or an attribute's value.
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
     * Refuse to be serialised: the claims live only for the completion that
     * verified them.
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
     * What `json_encode()` writes: the issuer, the NameID format, each
     * attribute's name with the kind of its value, and the redacted forms of
     * the authentication context, the linking email and, when there is one, the
     * asserted email; never the subject or an attribute's value.
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
