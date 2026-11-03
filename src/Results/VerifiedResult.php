<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;

/**
 * The output of a completed flow (SSO-8.1): the issuer, subject and connection,
 * under those names; the tenant, protocol, application and purpose; the
 * request's public reference; the mapped attributes, with whether the email's
 * domain is verified for the connection; the identity provider's authentication
 * context; where linking by a verified domain applies, the linking email, kept
 * apart from the mapped attributes; and, for OIDC, the email the provider
 * asserted with its `email_verified` and their one source (SSO-7.7), also kept
 * apart from the mapped attributes.
 *
 * It exists only after every check of SSO-6 or SSO-7 has passed: only the
 * completion pipeline builds one, from a driver's `VerifiedClaims`, and the
 * handoff store reads one back from its own encrypted storage. It is never
 * built from, or deserialised out of, client input. It holds no assertion,
 * token or secret, and it is never handed to an event whole: an event's context
 * takes its fields one by one (SSO-10.4).
 *
 * It is serialisable, as SSO-8.1 requires, so a handoff store can keep it until
 * redemption: `toArray()` (also what `serialize()` writes) holds everything
 * above and nothing else, and `restore()` (also what `unserialize()` runs)
 * checks every part again, failing with an `UnexpectedValueException` on
 * anything the package did not write. `json_encode()` writes the same, but for
 * the asserted email, which it shows only as its source and `email_verified`,
 * so the JSON of a result with one is not a stored form. A result with no
 * asserted email stores no key for one. It holds personal data (the mapped
 * attributes, the linking email, the asserted email), so a store encrypts it at
 * rest.
 *
 * The issuer and subject are 1 to 1024 bytes and kept exactly as received
 * (SSO-6.9); a NameID format is 1 to 255 bytes; the connection, tenant,
 * protocol and application are 1 to 255 bytes; each mapped attribute is a
 * string or a list of strings under a non-empty name.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class VerifiedResult implements \JsonSerializable
{
    /** @var int The longest issuer, in bytes. */
    public const int MAX_ISSUER_LENGTH = 1024;

    /** @var int The longest subject, in bytes (SSO-6.9). */
    public const int MAX_SUBJECT_LENGTH = 1024;

    /** @var int The longest NameID format, in bytes. */
    public const int MAX_NAME_ID_FORMAT_LENGTH = 255;

    /** @var int The longest connection id, tenant id, protocol or application, in bytes. */
    public const int MAX_ID_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $nameIdFormat
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Flows\RequestReference  $requestReference
     * @param  array<string, list<string>|string>  $attributes
     * @param  bool  $emailDomainVerified
     * @param  \SineMacula\Laravel\Sso\Results\AuthenticationContext  $authenticationContext
     * @param  ?\SineMacula\Laravel\Sso\Results\LinkingEmail  $linkingEmail
     * @param  ?\SineMacula\Laravel\Sso\Results\AssertedEmail  $assertedEmail
     *
     * @throws \InvalidArgumentException
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The identity provider's identifier. */
        public string $issuer,

        /** The person's stable identifier at the provider, exactly as received. */
        public string $subject,

        /** The SAML `NameID` format, part of the subject; `null` for OIDC or an attribute subject. */
        public ?string $nameIdFormat,

        /** The connection the flow completed through. */
        public string $connectionId,

        /** The opaque id of the connection's tenant. */
        public string $tenantId,

        /** The connection's protocol. */
        public string $protocol,

        /** The application the flow is for. */
        public string $application,

        /** What the flow is for. */
        public Purpose $purpose,

        /** The authorisation request's public reference. */
        public RequestReference $requestReference,

        /** The mapped attributes: profile data, never used to select an identity. */
        public array $attributes,

        /** Whether the mapped email's domain is verified for the connection. */
        public bool $emailDomainVerified,

        /** The identity provider's authentication context. */
        public AuthenticationContext $authenticationContext,

        /** The linking email, where linking by a verified domain applies. */
        public ?LinkingEmail $linkingEmail = null,

        /** The email and `email_verified` an OIDC provider asserted, from one source. */
        public ?AssertedEmail $assertedEmail = null,
    ) {
        StoredValues::assertText('issuer', $issuer, self::MAX_ISSUER_LENGTH);
        StoredValues::assertText('subject', $subject, self::MAX_SUBJECT_LENGTH);
        StoredValues::assertOptionalText('NameID format', $nameIdFormat, self::MAX_NAME_ID_FORMAT_LENGTH);

        foreach (['connection id' => $connectionId, 'tenant id' => $tenantId, 'protocol' => $protocol, 'application' => $application] as $name => $value) {
            StoredValues::assertText($name, $value, self::MAX_ID_LENGTH);
        }

        self::assertAttributes($attributes);
    }

    /**
     * What `serialize()` writes: the stored form.
     *
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        return $this->toArray();
    }

    /**
     * Rebuild from what `serialize()` wrote, checking every part again.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    public function __unserialize(array $data): void
    {
        $restored = self::restore($data);

        $this->issuer                = $restored->issuer;
        $this->subject               = $restored->subject;
        $this->nameIdFormat          = $restored->nameIdFormat;
        $this->connectionId          = $restored->connectionId;
        $this->tenantId              = $restored->tenantId;
        $this->protocol              = $restored->protocol;
        $this->application           = $restored->application;
        $this->purpose               = $restored->purpose;
        $this->requestReference      = $restored->requestReference;
        $this->attributes            = $restored->attributes;
        $this->emailDomainVerified   = $restored->emailDomainVerified;
        $this->authenticationContext = $restored->authenticationContext;
        $this->linkingEmail          = $restored->linkingEmail;
        $this->assertedEmail         = $restored->assertedEmail;
    }

    /**
     * The result as stored, with snake_case keys: everything it holds, and
     * nothing else; the asserted email only when it has one.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $stored = [
            'issuer'                 => $this->issuer,
            'subject'                => $this->subject,
            'name_id_format'         => $this->nameIdFormat,
            'connection_id'          => $this->connectionId,
            'tenant_id'              => $this->tenantId,
            'protocol'               => $this->protocol,
            'application'            => $this->application,
            'purpose'                => $this->purpose->value,
            'request_reference'      => $this->requestReference->value,
            'attributes'             => $this->attributes,
            'email_domain_verified'  => $this->emailDomainVerified,
            'authentication_context' => $this->authenticationContext->toArray(),
            'linking_email'          => $this->linkingEmail?->toArray(),
        ];

        return $this->assertedEmail === null ? $stored : [...$stored, 'asserted_email' => $this->assertedEmail->toArray()];
    }

    /**
     * The result `toArray()` stored, read back from the package's own storage;
     * never from client input.
     *
     * @param  array<array-key, mixed>  $stored
     * @return self
     *
     * @throws \UnexpectedValueException
     *
     * @internal
     */
    public static function restore(array $stored): self
    {
        $verified = StoredValues::isTrue($stored, 'email_domain_verified');
        $email    = StoredValues::optionalArray($stored, 'linking_email');
        $context  = AuthenticationContext::restore(StoredValues::array($stored, 'authentication_context'));
        $linking  = $email === null ? null : LinkingEmail::restore($email);
        $pair     = StoredValues::optionalArray($stored, 'asserted_email');
        $asserted = $pair === null ? null : AssertedEmail::restore($pair);

        return StoredValues::restoring(static fn (): self => new self(
            StoredValues::string($stored, 'issuer'),
            StoredValues::string($stored, 'subject'),
            StoredValues::optionalString($stored, 'name_id_format'),
            StoredValues::string($stored, 'connection_id'),
            StoredValues::string($stored, 'tenant_id'),
            StoredValues::string($stored, 'protocol'),
            StoredValues::string($stored, 'application'),
            Purpose::from(StoredValues::string($stored, 'purpose')),
            RequestReference::fromString(StoredValues::string($stored, 'request_reference')),
            StoredValues::array($stored, 'attributes'), // @phpstan-ignore argument.type
            $verified,
            $context,
            $linking,
            $asserted,
        ));
    }

    /**
     * What `json_encode()` writes: the stored form, but for the asserted email,
     * shown only as its source and `email_verified`.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        $stored = $this->toArray();

        return $this->assertedEmail === null ? $stored : array_replace($stored, ['asserted_email' => $this->assertedEmail->jsonSerialize()]);
    }

    /**
     * Refuse attributes that are not strings or lists of strings, each under a
     * non-empty name.
     *
     * @param  array<array-key, mixed>  $attributes
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertAttributes(array $attributes): void
    {
        foreach ($attributes as $name => $value) {
            if (!self::isAttributeName($name) || !self::isAttributeValue($value)) {
                throw new \InvalidArgumentException('A verified result\'s attributes are strings or lists of strings, each under a non-empty name.');
            }
        }
    }

    /**
     * Whether the key names an attribute: a non-empty string.
     *
     * @param  int|string  $name
     * @return bool
     */
    private static function isAttributeName(int|string $name): bool
    {
        return is_string($name) && $name !== '';
    }

    /**
     * Whether the value is an attribute's: a string, or a list of strings.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isAttributeValue(mixed $value): bool
    {
        if (is_string($value)) {
            return true;
        }

        return is_array($value) && array_is_list($value) && array_filter($value, is_string(...)) === $value;
    }
}
