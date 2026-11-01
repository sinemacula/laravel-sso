<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Secrets\MaskedSecret;

/**
 * Unit tests for a masked client secret: whether one is set, and nothing of it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MaskedSecret::class)]
final class MaskedSecretTest extends TestCase
{
    /**
     * A set secret reads as set; an unset one does not.
     *
     * @return void
     */
    public function testSetAndUnset(): void
    {
        self::assertTrue(MaskedSecret::set()->isSet);
        self::assertFalse(MaskedSecret::unset()->isSet);
    }

    /**
     * Its JSON is whether a secret is set, under `set`, and nothing else.
     *
     * @return void
     */
    public function testJson(): void
    {
        self::assertSame(['set' => true], MaskedSecret::set()->jsonSerialize());
        self::assertSame(['set' => false], MaskedSecret::unset()->jsonSerialize());
        self::assertSame('{"set":true}', json_encode(MaskedSecret::set()));
        self::assertSame('{"set":false}', json_encode(MaskedSecret::unset()));
    }

    /**
     * It holds nothing but whether a secret is set.
     *
     * @return void
     */
    public function testHoldsNothingButWhetherASecretIsSet(): void
    {
        $properties = array_map(
            static fn (\ReflectionProperty $property): string => $property->getName(),
            (new \ReflectionClass(MaskedSecret::class))->getProperties(),
        );

        self::assertSame(['isSet'], $properties);
    }
}
