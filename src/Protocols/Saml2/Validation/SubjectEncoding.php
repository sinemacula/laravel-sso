<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;

/**
 * The subject a SAML assertion's verified identifier is stored and compared as
 * (SSO-6.9): a versioned, length-prefixed tuple, so no choice of values makes
 * two different identifiers one subject.
 *
 * The encoding is `v1`, then, for each part in order, `|` and either the part's
 * length in bytes, `:` and the part itself, or `-` for a part that is absent,
 * so an absent part and an empty one (`0:`) are told apart.
 *
 * - A `NameID` is (`name_id`, its `Format`, its `NameQualifier`, its
 *   `SPNameQualifier`, its value), so a persistent `alice` with neither
 *   qualifier is `v1|7:name_id|52:urn:…:persistent|-|-|5:alice`.
 * - An attribute is (`attribute`, its `Name`, its `NameFormat`, its one value).
 *
 * Every part is kept exactly as the adapter read it from the verified element:
 * never trimmed, case-folded or normalised. A qualifier or format that appears,
 * disappears or changes therefore makes a different subject, and a link made
 * for one never matches the other. The caller caps the whole encoding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SubjectEncoding
{
    /** @var string The version the encoding starts with, naming its layout. */
    public const string VERSION = 'v1';

    /** @var string The kind of a subject taken from a `NameID`. */
    public const string NAME_ID = 'name_id';

    /** @var string The kind of a subject taken from an attribute. */
    public const string ATTRIBUTE = 'attribute';

    /** @var string What an absent part is written as. */
    private const string ABSENT = '-';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The subject of a `NameID`: its kind, format, qualifiers and value.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $nameId
     * @return string
     */
    public static function nameId(NameId $nameId): string
    {
        return self::encode([self::NAME_ID, $nameId->format(), $nameId->nameQualifier(), $nameId->spNameQualifier(), $nameId->value()]);
    }

    /**
     * The subject of an attribute's value: its kind, the attribute's name and
     * name format, and the value.
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
