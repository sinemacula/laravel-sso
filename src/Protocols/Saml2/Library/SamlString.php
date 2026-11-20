<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\XMLSchema\Exception\SchemaViolationException;

/**
 * The SAML library's validation of a NameID or attribute string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SamlString
{
    /**
     * Whether the library's string type accepts the value; under PCRE2 10.45 to
     * 10.47 it refuses every character above U+00FF.
     *
     * @param  string  $value
     * @return bool
     */
    public static function isValid(string $value): bool
    {
        try {
            SAMLStringValue::fromString($value);
            // The library declares no @throws.
            // @phpstan-ignore catch.neverThrown
        } catch (SchemaViolationException) {
            return false;
        }

        return true;
    }
}
