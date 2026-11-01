<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Secrets;

/**
 * Constant-time comparison (SSO-11.9): every secret, verifier, code and digest
 * the package compares goes through here, never through `===`, `==` or
 * `strcmp()`, whose time depends on how much of the two values agrees, so the
 * time a comparison takes tells an attacker nothing of the value it was
 * compared with.
 *
 * Only the length of the known value can show: `hash_equals()` returns at once
 * when the lengths differ, which is why a digest, of a fixed length, is the
 * form to compare a value of any length in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ConstantTime
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the given value is the known one, compared in constant time.
     *
     * @param  string  $known
     * @param  string  $given
     * @return bool
     */
    public static function equals(#[\SensitiveParameter] string $known, #[\SensitiveParameter] string $given): bool
    {
        return hash_equals($known, $given);
    }

    /**
     * Whether the value hashes to the known digest, compared in constant time.
     * The known digest is lower-case hex, as `hash()` writes it; the algorithm
     * is a cryptographic hash PHP supports (one `hash_hmac_algos()` lists), and
     * any other is a caller's mistake.
     *
     * @param  string  $knownHexDigest
     * @param  string  $value
     * @param  string  $algorithm
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public static function matchesDigest(string $knownHexDigest, #[\SensitiveParameter] string $value, string $algorithm = 'sha256'): bool
    {
        if (!in_array($algorithm, hash_hmac_algos(), true)) {
            throw new \InvalidArgumentException("The digest algorithm [{$algorithm}] is not a cryptographic hash PHP supports.");
        }

        return hash_equals($knownHexDigest, hash($algorithm, $value));
    }
}
