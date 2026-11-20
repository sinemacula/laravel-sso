<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlString;

/**
 * Unit tests for the SAML library's validation of a string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SamlString::class)]
final class SamlStringTest extends TestCase
{
    /**
     * A string of XML characters is valid, and one with a control character is
     * not.
     *
     * @return void
     */
    public function testOnlyXmlCharactersAreValid(): void
    {
        self::assertSame([true, false], [SamlString::isValid('alice'), SamlString::isValid("al\u{1}ice")]);
    }
}
