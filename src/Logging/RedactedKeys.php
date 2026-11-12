<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

/**
 * Matches a key against the redacted keys, shared by the redactor and the
 * sanitiser so both redact the same keys.
 *
 * A key matches when, fully decoded, a run of its words normalises to a
 * redacted key, so `user[password]` matches but `error_code` does not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RedactedKeys
{
    /** @var int Decode passes; a key still encoded after them is redacted. */
    public const int MAX_DECODES = 8;

    /** @var int Bytes of the text before a key read for words that may name it. */
    private const int LOOKBACK = 128;

    /** @var string What separates the words of a key. */
    private const string SEPARATORS = '/[^A-Za-z0-9_]+/';

    /** @var array<string, int> The normalised redacted keys, as array keys. */
    private array $keys;

    /** @var int The longest normalised redacted key, past which no run matches. */
    private int $longest;

    /**
     * Constructor.
     *
     * @param  list<string>  $keys
     */
    public function __construct(array $keys)
    {
        $this->keys    = array_flip($keys);
        $this->longest = max([0, ...array_map(strlen(...), $keys)]);
    }

    /**
     * The built-in and configured redacted keys.
     *
     * @param  \SineMacula\Laravel\Sso\Logging\LoggingSettings  $settings
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function from(LoggingSettings $settings): self
    {
        return new self($settings->redactedKeys());
    }

    /**
     * Whether a value under the key is redacted.
     *
     * @param  string  $key
     * @return bool
     */
    public function matches(string $key): bool
    {
        return $this->matchesAfter('', $key);
    }

    /**
     * Whether a key found in text is redacted, counting runs that start in the
     * preceding words (`private key=`) but never runs ending before the key.
     *
     * @param  string  $before
     * @param  string  $key
     * @return bool
     */
    public function matchesAfter(string $before, string $key): bool
    {
        $key   = self::words(self::decode($key));
        $prior = strlen($before) > self::LOOKBACK
            ? array_slice(self::words(self::decode(substr($before, -self::LOOKBACK)) ?? '') ?? [], 1)
            : self::words(self::decode($before) ?? '') ?? [];

        if ($key === null) {
            return true;
        }

        return $this->hasRun([...$prior, ...$key], count($prior));
    }

    /**
     * Whether a run ending at or after `$first` is a redacted key; capping runs
     * at the longest key keeps this linear.
     *
     * @param  list<string>  $words
     * @param  int  $first
     * @return bool
     */
    private function hasRun(array $words, int $first): bool
    {
        $count = count($words);

        for ($start = 0; $start < $count; $start++) {

            $run = '';

            for ($end = $start; $end < $count && strlen($run) <= $this->longest; $end++) {

                $run .= LoggingSettings::normalizeKey($words[$end]);

                if ($end >= $first && isset($this->keys[$run])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The words of the key; `null`, taken for a match, when unreadable.
     *
     * @param  ?string  $key
     * @return ?list<string>
     */
    private static function words(?string $key): ?array
    {
        $words = $key === null ? false : preg_split(self::SEPARATORS, $key, -1, PREG_SPLIT_NO_EMPTY);

        return $words === false ? null : $words;
    }

    /**
     * URL-decode the key repeatedly; `null` if still encoded after
     * `MAX_DECODES` passes.
     *
     * @param  string  $key
     * @return ?string
     */
    private static function decode(string $key): ?string
    {
        for ($pass = 0; $pass <= self::MAX_DECODES; $pass++) {

            $decoded = urldecode($key);

            if ($decoded === $key) {
                return $key;
            }

            $key = $decoded;
        }

        return null;
    }
}
