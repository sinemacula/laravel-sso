<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;

/**
 * The encoded subject of a verified SAML assertion by the connection's
 * `subject_source`; an over-long one is refused, never truncated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SubjectRules
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The encoded subject and its NameID format, or why there is none; an
     * unknown source fails closed.
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
     * The encoded subject of the `NameID`, or `null` if it is not accepted.
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
     * Whether the `NameID` has a value and an accepted format and qualifiers.
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
     * Whether the format is the connection's URI exactly; an absent one means
     * `unspecified` (SAML 2.0 Core 8.3.1).
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $nameId
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isFormat(NameId $nameId, ValidationContext $context): bool
    {
        $format = $nameId->format();

        return $format === null ? $context->options->nameIdFormat === 'unspecified' : $format === $context->options->nameIdFormatUri();
    }

    /**
     * Whether each qualifier is absent or names its party exactly.
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
     * The encoded subject of the one attribute of the name with one non-empty
     * value, or `null`.
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
     * Whether the encoded subject fits a link.
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
