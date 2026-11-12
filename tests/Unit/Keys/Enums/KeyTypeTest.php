<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;

/**
 * Unit tests for the key types.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyType::class)]
final class KeyTypeTest extends TestCase
{
    /**
     * The types are these, in this order: a value is never renamed or reused.
     *
     * @return void
     */
    public function testTheTypesAreStable(): void
    {
        self::assertSame(['rsa', 'ec'], array_column(KeyType::cases(), 'value'));
    }

    /**
     * Each case's name is its value in upper case.
     *
     * @return void
     */
    public function testEachNameIsItsValue(): void
    {
        foreach (KeyType::cases() as $type) {
            self::assertSame(strtoupper($type->value), $type->name);
        }
    }
}
