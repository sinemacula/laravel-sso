<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\IdTokens;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens\AccessTokenHash;

/**
 * Unit tests for an ID token's `at_hash` (OpenID Connect Core §3.1.3.8,
 * SSO-7.4): the left half of the access token's hash for each algorithm size,
 * pinned against values computed apart from the package, absent accepted, and
 * every near miss refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessTokenHash::class)]
final class AccessTokenHashTest extends TestCase
{
    /** @var string The access token every value is the hash of. */
    private const string ACCESS_TOKEN = 'the-access-token';

    /** @var string The left half of its SHA-256, encoded. */
    private const string SHA256 = 'uby9Z8Gb_H_x4fPjwNzguw';

    /** @var string The left half of its SHA-384, encoded. */
    private const string SHA384 = '9gqw8f3voYDv2u5y8ObTDrn9GOrdAzTZ';

    /** @var string The left half of its SHA-512, encoded. */
    private const string SHA512 = 'B7p8o12G5vm-9CEZGSanwzMw-leqyauPjU1ebdjBHYw';

    /**
     * Rows of `[algorithm, at_hash]`: every algorithm with its hash's value.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideAlgorithms(): iterable
    {
        yield from [
            'RS256' => ['RS256', self::SHA256],
            'PS256' => ['PS256', self::SHA256],
            'ES256' => ['ES256', self::SHA256],
            'RS384' => ['RS384', self::SHA384],
            'PS384' => ['PS384', self::SHA384],
            'ES384' => ['ES384', self::SHA384],
            'RS512' => ['RS512', self::SHA512],
            'PS512' => ['PS512', self::SHA512],
            'ES512' => ['ES512', self::SHA512],
        ];
    }

    /**
     * Each algorithm's size chooses its hash, of which the left half is taken.
     *
     * @param  string  $algorithm
     * @param  string  $hash
     * @return void
     */
    #[DataProvider('provideAlgorithms')]
    public function testEachAlgorithmsHashIsAccepted(string $algorithm, string $hash): void
    {
        self::assertSame($hash, AccessTokenHash::of(self::ACCESS_TOKEN, $algorithm));
        self::assertNull(AccessTokenHash::refusal(['at_hash' => $hash], self::ACCESS_TOKEN, $algorithm));
    }

    /**
     * An `at_hash` of another hash size is refused under each algorithm.
     *
     * @param  string  $algorithm
     * @param  string  $hash
     * @return void
     */
    #[DataProvider('provideAlgorithms')]
    public function testAnotherSizesHashIsRefused(string $algorithm, string $hash): void
    {
        foreach (array_diff([self::SHA256, self::SHA384, self::SHA512], [$hash]) as $other) {
            self::assertSame(FailureReason::AT_HASH_MISMATCH, AccessTokenHash::refusal(['at_hash' => $other], self::ACCESS_TOKEN, $algorithm));
        }
    }

    /**
     * Rows of `[at_hash]`: a near miss of the SHA-256 value.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideWrongHashes(): iterable
    {
        $whole = rtrim(strtr(base64_encode(hash('sha256', self::ACCESS_TOKEN, true)), '+/', '-_'), '=');

        yield from [
            'another token'   => [rtrim(strtr(base64_encode(substr(hash('sha256', 'another-token', true), 0, 16)), '+/', '-_'), '=')],
            'the whole hash'  => [$whole],
            'one byte short'  => [rtrim(strtr(base64_encode(substr(hash('sha256', self::ACCESS_TOKEN, true), 0, 15)), '+/', '-_'), '=')],
            'one byte over'   => [rtrim(strtr(base64_encode(substr(hash('sha256', self::ACCESS_TOKEN, true), 0, 17)), '+/', '-_'), '=')],
            'the right half'  => [rtrim(strtr(base64_encode(substr(hash('sha256', self::ACCESS_TOKEN, true), 16)), '+/', '-_'), '=')],
            'padded'          => [self::SHA256 . '=='],
            'plain base64'    => [base64_encode(substr(hash('sha256', self::ACCESS_TOKEN, true), 0, 16))],
            'another case'    => [strtoupper(self::SHA256)],
            'with whitespace' => [self::SHA256 . ' '],
            'hex'             => [substr(hash('sha256', self::ACCESS_TOKEN), 0, 32)],
            'empty'           => [''],
            'an array'        => [[self::SHA256]],
            'a number'        => [1],
            'null'            => [null],
        ];
    }

    /**
     * A wrong `at_hash` is `at_hash_mismatch`.
     *
     * @param  mixed  $hash
     * @return void
     */
    #[DataProvider('provideWrongHashes')]
    public function testAWrongHashIsRefused(mixed $hash): void
    {
        self::assertSame(FailureReason::AT_HASH_MISMATCH, AccessTokenHash::refusal(['at_hash' => $hash], self::ACCESS_TOKEN, 'RS256'));
    }

    /**
     * Rows of `[algorithm]`: one whose size names no hash, which only a misuse
     * could reach, since the allow-list holds none of them.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnknownAlgorithms(): iterable
    {
        yield from [
            'none'            => ['none'],
            'a size unknown'  => ['RS224'],
            'a zero-led size' => ['RS0256'],
            'a size and text' => ['RS256x'],
            'empty'           => [''],
            'a short name'    => ['RS'],
        ];
    }

    /**
     * An algorithm whose size names no hash refuses a token that has `at_hash`
     * and says nothing of one that has none.
     *
     * @param  string  $algorithm
     * @return void
     */
    #[DataProvider('provideUnknownAlgorithms')]
    public function testAnUnknownAlgorithmFailsClosed(string $algorithm): void
    {
        self::assertNull(AccessTokenHash::of(self::ACCESS_TOKEN, $algorithm));
        self::assertSame(FailureReason::AT_HASH_MISMATCH, AccessTokenHash::refusal(['at_hash' => self::SHA256], self::ACCESS_TOKEN, $algorithm));
        self::assertNull(AccessTokenHash::refusal([], self::ACCESS_TOKEN, $algorithm));
    }

    /**
     * An absent `at_hash` is accepted, as the code flow allows.
     *
     * @return void
     */
    public function testAnAbsentHashIsAccepted(): void
    {
        self::assertNull(AccessTokenHash::refusal([], self::ACCESS_TOKEN, 'RS256'));
        self::assertNull(AccessTokenHash::refusal(['sub' => 'person'], self::ACCESS_TOKEN, 'ES512'));
    }
}
