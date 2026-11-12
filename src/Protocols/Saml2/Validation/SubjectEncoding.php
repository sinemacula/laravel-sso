<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;

/**
 * Encodes a verified SAML identifier as a stored subject: a versioned,
 * length-prefixed tuple, unnormalised. The caller caps its length.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SubjectEncoding
{
    /** @var string The version prefix naming the layout. */
    public const string VERSION = 'v1';

    /** @var string The kind of a subject taken from a `NameID`. */
    public const string NAME_ID = 'name_id';

    /** @var string The kind of a subject taken from an attribute. */
    public const string ATTRIBUTE = 'attribute';

    /** @var string An absent part, distinct from an empty one (`0:`). */
    private const string ABSENT = '-';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The subject of a `NameID`, e.g.
     * `v1|7:name_id|52:urn:...:persistent|-|-|5:alice`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $nameId
     * @return string
     */
    public static function nameId(NameId $nameId): string
    {
        return self::encode([self::NAME_ID, $nameId->format(), $nameId->nameQualifier(), $nameId->spNameQualifier(), $nameId->value()]);
    }

    /**
     * The subject of an attribute's value.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute  $attribute
     * @param  string  $value
     * @return string
     */
    public static function attribute(SamlAttribute $attribute, #[\SensitiveParameter] string $value): string
    {
        return self::encode([self::ATTRIBUTE, $attribute->name(), $attribute->nameFormat(), $value]);
    }

    /**
     * The version, then each part length-prefixed, or `-` when absent.
     *
     * @param  list<?string>  $parts
     * @return string
     */
    private static function encode(#[\SensitiveParameter] array $parts): string
    {
        $encoded = array_map(static fn (?string $part): string => '|' . ($part === null ? self::ABSENT : strlen($part) . ':' . $part), $parts);

        return self::VERSION . implode('', $encoded);
    }
}
