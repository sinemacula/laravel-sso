<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;

/**
 * Unit tests for where a key of the service provider's own is in its rotation:
 * stable values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyState::class)]
final class KeyStateTest extends TestCase
{
    /**
     * The states are these, in this order: a value is never renamed or reused.
     *
     * @return void
     */
    public function testTheStatesAreStable(): void
    {
        self::assertSame(['next', 'current', 'retiring'], array_column(KeyState::cases(), 'value'));
    }

    /**
     * Each case's name is its value in upper case.
     *
     * @return void
     */
    public function testEachNameIsItsValue(): void
    {
        foreach (KeyState::cases() as $state) {
            self::assertSame(strtoupper($state->value), $state->name);
        }
    }
}
