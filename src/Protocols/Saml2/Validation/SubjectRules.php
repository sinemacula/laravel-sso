<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;

/**
 * The subject of a verified SAML assertion (SSO-6.9), by the connection's
 * `subject_source`, as `SubjectEncoding` writes it, or `subject_invalid`:
 *
 * - `name_id`: the subject carries a `NameID` with a non-empty value; its
 *   `Format` is the connection's `name_id_format` URI exactly, and an absent
 *   `Format` is accepted only when that is `unspecified` (SAML 2.0 Core
 *   §8.3.1), so a transient `NameID` is never a subject and the email and
 *   unspecified formats only by opt-in; its `NameQualifier` is absent or the
 *   identity provider's entity id, and its `SPNameQualifier` absent or the
 *   service provider's, each compared exactly. The claims' NameID format is the
 *   connection's format URI.
 * - `attribute`: exactly one `Attribute` whose `Name` is exactly
 *   `subject_attribute`, with exactly one value, a non-empty string. The claims
 *   carry no NameID format.
 * - any other source fails closed.
 *
 * The encoded subject must be at most `LinkSubject::MAX_SUBJECT_LENGTH` bytes;
 * a longer one is refused, never truncated. Nothing here keeps anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SubjectRules
{
    /** @var string The NameID format that may also be given by no `Format` at all. */
    private const string UNSPECIFIED = 'unspecified';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The encoded subject and its NameID format, or why the assertion has no
     * subject the connection accepts.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return array{0: string, 1: ?string}|\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function subject(SamlAssertion $assertion, ValidationContext $context): array|FailureReason
    {
        $options = $context->options;

        [$subject, $format] = match ($options->subjectSource) {
            'name_id'   => [self::fromNameId($assertion->subject()?->nameId(), $context), $options->nameIdFormatUri()],
            'attribute' => [self::fromAttribute($assertion->attributes(), $options->subjectAttribute), null],
            default     => [null, null],
        };

        return self::isStorable($subject) ? [$subject, $format] : FailureReason::SUBJECT_INVALID;
    }

    /**
     * The encoded subject of the `NameID`, or `null` when the connection does
     * not accept it.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $nameId
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?string
     */
    private static function fromNameId(?NameId $nameId, ValidationContext $context): ?string
    {
        if ($nameId === null || !self::isAccepted($nameId, $context)) {
            return null;
        }

        return SubjectEncoding::nameId($nameId);
    }

    /**
     * Whether the connection accepts the `NameID`: a non-empty value, its
     * format and its qualifiers.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $nameId
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isAccepted(NameId $nameId, ValidationContext $context): bool
    {
        return $nameId->value() !== '' && self::isFormat($nameId, $context) && self::isQualified($nameId, $context);
    }

    /**
     * Whether the `NameID`'s format is the connection's: its URI exactly, or
     * absent when the connection accepts `unspecified`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $nameId
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isFormat(NameId $nameId, ValidationContext $context): bool
    {
        $format = $nameId->format();

        return $format === null ? $context->options->nameIdFormat === self::UNSPECIFIED : $format === $context->options->nameIdFormatUri();
    }

    /**
     * Whether each qualifier of the `NameID` is absent or names its party
     * exactly.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $nameId
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isQualified(NameId $nameId, ValidationContext $context): bool
    {
        $nameQualifier   = $nameId->nameQualifier();
        $spNameQualifier = $nameId->spNameQualifier();

        $identityProvider = $nameQualifier   === null || $context->isIdentityProvider($nameQualifier);
        $serviceProvider  = $spNameQualifier === null || $spNameQualifier === $context->serviceProviderEntityId;

        return $identityProvider && $serviceProvider;
    }

    /**
     * The encoded subject of the one value of the one attribute with exactly
     * the name, or `null` when there is not exactly one, with exactly one
     * non-empty string value.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute>  $attributes
     * @param  ?string  $name
     * @return ?string
     */
    private static function fromAttribute(array $attributes, ?string $name): ?string
    {
        $named     = array_values(array_filter($attributes, static fn (SamlAttribute $attribute): bool => $attribute->name() === $name));
        $attribute = count($named) === 1 ? $named[0] : null;
        $values    = $attribute?->values() ?? [];
        $value     = (string) (count($values) === 1 ? $values[0] : null);

        return $attribute === null || $value === '' ? null : SubjectEncoding::attribute($attribute, $value);
    }

    /**
     * Whether the encoded subject is one a link can hold.
     *
     * @param  ?string  $subject
     * @return bool
     *
     * @phpstan-assert-if-true string $subject
     */
    private static function isStorable(?string $subject): bool
    {
        return $subject !== null && strlen($subject) <= LinkSubject::MAX_SUBJECT_LENGTH;
    }
}
