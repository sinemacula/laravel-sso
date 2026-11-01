<?php

declare(strict_types = 1);

namespace Tests\Unit\Handoffs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;

/**
 * Unit tests for a handoff code: 43 random base64url characters, stored only as
 * its SHA-256 digest, matched in constant time, and never shown in a dump, JSON
 * or a serialisation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffCode::class)]
final class HandoffCodeTest extends TestCase
{
    /**
     * A generated code is 43 base64url characters and new each time; its digest
     * is the lower-case hex SHA-256 of it, and it matches only that.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGeneratesARandomCode(): void
    {
        $one = HandoffCode::generate();
        $two = HandoffCode::generate();

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $one->reveal());
        self::assertNotSame($one->reveal(), $two->reveal());
        self::assertSame(hash('sha256', $one->reveal()), $one->digest());
        self::assertTrue($one->matches($one->digest()));
        self::assertFalse($one->matches($two->digest()));
        self::assertFalse($one->matches(strtoupper($one->digest())));
    }

    /**
     * A code is exactly 43 base64url characters.
     *
     * @return void
     */
    public function testAcceptsOnlyACodesForm(): void
    {
        self::assertSame(43, HandoffCode::LENGTH);
        self::assertSame(str_repeat('c', 43), HandoffCode::fromString(str_repeat('c', 43))->reveal());

        foreach ([str_repeat('a', 42), str_repeat('a', 44), str_repeat('a', 42) . '~', str_repeat('a', 43) . "\n", ''] as $value) {
            self::assertFalse(HandoffCode::isWellFormed($value), $value);
        }

        $this->expectExceptionObject(new \InvalidArgumentException('A handoff code is 43 base64url characters.'));

        HandoffCode::fromString(str_repeat('a', 42));
    }

    /**
     * Neither a dump nor JSON shows the code.
     *
     * @return void
     */
    public function testNeverShowsTheCode(): void
    {
        $code = HandoffCode::fromString(str_repeat('s', 43));

        self::assertStringNotContainsString(str_repeat('s', 43), print_r($code, true));
        self::assertSame(['code' => '[redacted]'], $code->__debugInfo());
        self::assertSame('"[redacted]"', json_encode($code));
    }

    /**
     * A code cannot be serialised.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testCannotBeSerialised(): void
    {
        $this->expectExceptionObject(new \LogicException('A handoff code cannot be serialised.'));

        serialize(HandoffCode::generate());
    }

    /**
     * A code cannot be unserialised.
     *
     * @return void
     */
    public function testCannotBeUnserialised(): void
    {
        $this->expectExceptionObject(new \LogicException('A handoff code cannot be unserialised.'));

        unserialize('O:43:"SineMacula\Laravel\Sso\Handoffs\HandoffCode":0:{}');
    }
}
