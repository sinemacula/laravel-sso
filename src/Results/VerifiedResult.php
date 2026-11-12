<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Results;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;

/**
 * The output of a completed flow, built only by the completion pipeline or
 * restored from the package's own storage, never from client input.
 *
 * It holds personal data, so stores encrypt it at rest; unserialising checks
 * every part again.
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

    /** @var int The longest subject, in bytes. */
    public const int MAX_SUBJECT_LENGTH = 1024;

    /** @var int The longest NameID format, in bytes. */
    public const int MAX_NAME_ID_FORMAT_LENGTH = 255;

    /** @var int The longest connection, tenant, protocol or application, in bytes. */
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

        /** The SAML `NameID` format; `null` for OIDC or an attribute subject. */
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
     * The stored form; the asserted email key only when there is one.
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
     * Restore `toArray()` output from package storage, never client input.
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
     * The stored form with the asserted email redacted, so not a stored form.
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
     * Refuse attributes other than named strings or lists of strings.
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
     * Whether the key is a non-empty string.
     *
     * @param  int|string  $name
     * @return bool
     */
    private static function isAttributeName(int|string $name): bool
    {
        return is_string($name) && $name !== '';
    }

    /**
     * Whether the value is a string or a list of strings.
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
