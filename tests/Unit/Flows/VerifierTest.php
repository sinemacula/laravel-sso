<?php

declare(strict_types = 1);

namespace Tests\Unit\Flows;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Flows\Verifier;

/**
 * Unit tests for the client's handoff verifier: 43 to 128 unreserved
 * characters, generated from 256 random bits, never shown in a dump, JSON or a
 * serialisation, and compared in constant time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Verifier::class)]
final class VerifierTest extends TestCase
{
    /**
     * A generated verifier is 43 base64url characters, new each time, and its
     * challenge is its S256 challenge.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGeneratesARandomVerifier(): void
    {
        $one = Verifier::generate();
        $two = Verifier::generate();

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $one->reveal());
        self::assertFalse($one->equals($two));
        self::assertTrue($one->equals(Verifier::fromString($one->reveal())));
        self::assertSame(S256Challenge::of($one)->value, $one->challenge()->value);
    }

    /**
     * A verifier is 43 to 128 unreserved characters, and nothing else.
     *
     * @return void
     */
    public function testAcceptsOnlyAVerifiersForm(): void
    {
        self::assertSame(43, Verifier::MIN_LENGTH);
        self::assertSame(128, Verifier::MAX_LENGTH);

        foreach ([str_repeat('a', 43), str_repeat('a', 128), str_repeat('A-._~z9', 7) . 'a'] as $value) {
            self::assertTrue(Verifier::isWellFormed($value), $value);
            self::assertSame($value, Verifier::fromString($value)->reveal());
        }

        foreach ([str_repeat('a', 42), str_repeat('a', 129), str_repeat('a', 42) . '+', str_repeat('a', 42) . '=', str_repeat('a', 43) . "\n", ''] as $value) {
            self::assertFalse(Verifier::isWellFormed($value), $value);
        }

        $this->expectExceptionObject(new \InvalidArgumentException('A verifier is 43 to 128 unreserved characters.'));

        Verifier::fromString(str_repeat('a', 42));
    }

    /**
     * Neither a dump nor JSON shows the verifier.
     *
     * @return void
     */
    public function testNeverShowsTheVerifier(): void
    {
        $verifier = Verifier::fromString(str_repeat('s', 43));

        self::assertStringNotContainsString(str_repeat('s', 43), print_r($verifier, true));
        self::assertStringNotContainsString(str_repeat('s', 43), var_export($verifier, true));
        self::assertSame(['verifier' => '[redacted]'], $verifier->__debugInfo());
        self::assertSame('"[redacted]"', json_encode($verifier));
    }

    /**
     * A verifier cannot be serialised.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testCannotBeSerialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A verifier cannot be serialised.'));

        serialize(Verifier::generate());
    }

    /**
     * A verifier cannot be unserialised.
     *
     * @return void
     */
    public function testCannotBeUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A verifier cannot be unserialised.'));

        unserialize('O:37:"SineMacula\Laravel\Sso\Flows\Verifier":0:{}');
    }
}
