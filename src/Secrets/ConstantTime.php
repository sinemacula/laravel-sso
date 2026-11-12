<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Secrets;

/**
 * Constant-time comparison for every secret, verifier, code and digest.
 *
 * `hash_equals()` still leaks length, so compare variable-length values as
 * digests.
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
     * Whether the given value is the known one.
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
     * Whether the value hashes to the known lower-case hex digest.
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
