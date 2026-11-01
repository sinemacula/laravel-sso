<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * Unit tests for constant-time comparison: of two values, of a value with a
 * digest under each algorithm, and the refusal of an algorithm that is not a
 * cryptographic hash.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConstantTime::class)]
final class ConstantTimeTest extends TestCase
{
    /** @var string A value to compare. */
    private const string VALUE = 'the-verifier-value';

    /**
     * Equal values are equal; a value differing in content, case or length is
     * not.
     *
     * @return void
     */
    public function testEquals(): void
    {
        self::assertTrue(ConstantTime::equals(self::VALUE, self::VALUE));
        self::assertTrue(ConstantTime::equals('', ''));

        self::assertFalse(ConstantTime::equals(self::VALUE, 'the-verifier-valuE'));
        self::assertFalse(ConstantTime::equals(self::VALUE, 'THE-VERIFIER-VALUE'));
        self::assertFalse(ConstantTime::equals(self::VALUE, self::VALUE . 'x'));
        self::assertFalse(ConstantTime::equals(self::VALUE, substr(self::VALUE, 0, -1)));
        self::assertFalse(ConstantTime::equals(self::VALUE, ''));
    }

    /**
     * Rows of `[algorithm]`: algorithms a digest is compared under.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAlgorithms(): iterable
    {
        yield 'sha256' => ['sha256'];
        yield 'sha512' => ['sha512'];
    }

    /**
     * A value matches its own digest under the algorithm, and no other value's
     * or algorithm's.
     *
     * @param  string  $algorithm
     * @return void
     */
    #[DataProvider('provideAlgorithms')]
    public function testMatchesDigest(string $algorithm): void
    {
        $digest = hash($algorithm, self::VALUE);

        self::assertTrue(ConstantTime::matchesDigest($digest, self::VALUE, $algorithm));

        self::assertFalse(ConstantTime::matchesDigest($digest, self::VALUE . 'x', $algorithm));
        self::assertFalse(ConstantTime::matchesDigest(strtoupper($digest), self::VALUE, $algorithm));
        self::assertFalse(ConstantTime::matchesDigest(hash($algorithm === 'sha256' ? 'sha512' : 'sha256', self::VALUE), self::VALUE, $algorithm));
    }

    /**
     * The algorithm defaults to SHA-256.
     *
     * @return void
     */
    public function testTheDigestAlgorithmDefaultsToSha256(): void
    {
        self::assertTrue(ConstantTime::matchesDigest(hash('sha256', self::VALUE), self::VALUE));
        self::assertFalse(ConstantTime::matchesDigest(hash('sha512', self::VALUE), self::VALUE));
    }

    /**
     * Rows of `[algorithm]`: algorithms that are not cryptographic hashes PHP
     * supports.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnknownAlgorithms(): iterable
    {
        yield 'unknown' => ['sha-unknown'];
        yield 'empty' => [''];
        yield 'a checksum' => ['crc32b'];
        yield 'another case' => ['SHA256'];
    }

    /**
     * An algorithm that is not a cryptographic hash is a caller's mistake.
     *
     * @param  string  $algorithm
     * @return void
     */
    #[DataProvider('provideUnknownAlgorithms')]
    public function testRefusesAnUnknownAlgorithm(string $algorithm): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("The digest algorithm [{$algorithm}] is not a cryptographic hash PHP supports.");

        ConstantTime::matchesDigest(hash('sha256', self::VALUE), self::VALUE, $algorithm);
    }

    /**
     * It is a utility container, never instantiated.
     *
     * @return void
     */
    public function testCannotBeInstantiated(): void
    {
        $constructor = (new \ReflectionClass(ConstantTime::class))->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());
    }
}
