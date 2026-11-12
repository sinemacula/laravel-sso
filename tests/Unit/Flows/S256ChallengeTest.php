<?php

declare(strict_types = 1);

namespace Tests\Unit\Flows;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Flows\Verifier;

/**
 * Unit tests for a verifier's S256 challenge.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(S256Challenge::class)]
final class S256ChallengeTest extends TestCase
{
    /**
     * The challenge of a verifier is its unpadded base64url SHA-256 digest.
     *
     * @return void
     */
    public function testIsTheVerifiersDigest(): void
    {
        $verifier = Verifier::fromString(str_repeat('v', 43));
        $expected = rtrim(strtr(base64_encode(hash('sha256', str_repeat('v', 43), true)), '+/', '-_'), '=');

        self::assertSame($expected, S256Challenge::of($verifier)->value);
        self::assertSame(43, strlen($expected));
        self::assertSame(43, S256Challenge::LENGTH);
    }

    /**
     * A challenge is satisfied only by its own verifier.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIsSatisfiedOnlyByItsVerifier(): void
    {
        $verifier  = Verifier::generate();
        $challenge = S256Challenge::fromString($verifier->challenge()->value);

        self::assertTrue($challenge->isSatisfiedBy($verifier));
        self::assertFalse($challenge->isSatisfiedBy(Verifier::generate()));
        self::assertFalse(S256Challenge::fromString(str_repeat('a', 43))->isSatisfiedBy($verifier));
    }

    /**
     * A challenge is exactly 43 base64url characters.
     *
     * @return void
     */
    public function testAcceptsOnlyAChallengesForm(): void
    {
        self::assertTrue(S256Challenge::isWellFormed(str_repeat('a', 43)));

        foreach ([str_repeat('a', 42), str_repeat('a', 44), str_repeat('a', 42) . '=', str_repeat('a', 42) . '.', str_repeat('a', 43) . "\n"] as $value) {
            self::assertFalse(S256Challenge::isWellFormed($value), $value);
        }

        $this->expectExceptionObject(new \InvalidArgumentException('An S256 challenge is 43 base64url characters.'));

        S256Challenge::fromString(str_repeat('a', 44));
    }
}
