<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

/**
 * The redacted keys and the one way a key is matched against them, shared by
 * the context redactor and the diagnostic sanitiser, so a key one of them
 * redacts the other does too (SSO-5.7, SSO-9.8, SSO-11.9).
 *
 * A key matches when, decoded, a run of its words normalises to a redacted key
 * (see `LoggingSettings::normalizeKey()`). Decoding undoes percent-encoding,
 * and `+` for a space, as many times as the key was encoded, so
 * `client%5Fsecret`, `client%255Fsecret` and `client+secret` are all
 * `client_secret`; a key still encoded after `MAX_DECODES` passes matches,
 * since what cannot be read is taken for a secret's name. Its words are what
 * lies between anything but a letter, a digit and `_`, so `private key`, a
 * form's `user[password]`, a namespaced `oidc:client_secret`, a dotted
 * `credentials.password`, a path's `user/password` and a header's
 * `X-Client-Secret` all match, as does the whole of `Client-Secret`. A key
 * whose one word only contains a redacted key among other characters
 * (`error_code`, `token_type`) does not.
 *
 * A key found in text may also be named by the words just before it, run on
 * into it (`private key=…`, `SAML response: …`): `matchesAfter()` counts a run
 * of words that starts before the key and reaches into it, but never one that
 * ends before it, so a redacted key in the prose before a pair is not taken for
 * the pair's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RedactedKeys
{
    /** @var int The most times a key is decoded; one still encoded after that is taken for a redacted one. */
    public const int MAX_DECODES = 8;

    /** @var int The most bytes of the text before a key read for words that may name it. */
    private const int LOOKBACK = 128;

    /** @var string What separates the words of a key: anything but a letter, a digit and `_`. */
    private const string SEPARATORS = '/[^A-Za-z0-9_]+/';

    /** @var array<string, int> The normalised redacted keys, as the keys of the array. */
    private array $keys;

    /** @var int The length of the longest normalised redacted key, past which no run of words can match. */
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
     * The redacted keys the settings give: the built-in ones and those
     * configured.
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
     * Whether a value under the key is redacted: the key, decoded, has a run of
     * words that normalises to a redacted key.
     *
     * @param  string  $key
     * @return bool
     */
    public function matches(string $key): bool
    {
        return $this->matchesAfter('', $key);
    }

    /**
     * Whether a value under the key, found in text straight after the text
     * given, is redacted: the key matches, or a run of words that starts in the
     * last words of the text before it and reaches into the key does.
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
     * Whether a run of the words, ending at or after the word at the index
     * given, normalises to a redacted key. A run is not read past the length of
     * the longest key, so the words are read in time linear in their number.
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
     * The words of the key, or `null` when it is `null` (encoded past reading)
     * or cannot be split (a PCRE limit), either of which the caller takes for a
     * match.
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
     * The key with its percent-encoding and `+` for a space undone until
     * nothing is left to undo, or `null` when something still is after
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
