<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * The strict JSON decoder for every JOSE document: a top-level object with no
 * member name repeated at any depth, compared after escapes are read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StrictJson
{
    /** @var int The deepest nesting accepted, counting the top-level object. */
    public const int MAX_DEPTH = 32;

    /** @var int The flags a document is decoded with, keeping digits. */
    private const int DIGITS = JSON_BIGINT_AS_STRING | JSON_THROW_ON_ERROR;

    /** @var string A string literal or a structural character of valid JSON. */
    private const string TOKENS = '/"(?:[^"\\\]++|\\\.)*+"|[{}\[\],:]/s';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The object's members, or `null` when refused. An oversized integer stays
     * a string of digits, so a string-typed reader must not use this.
     *
     * @param  string  $json
     * @return ?array<array-key, mixed>
     */
    public static function decodeObject(#[\SensitiveParameter] string $json): ?array
    {
        $decoded = self::decoded($json);

        if (!is_array($decoded) || ltrim($json, " \t\n\r")[0] !== '{') {
            return null;
        }

        return self::mayRepeatMember($json) ? null : $decoded;
    }

    /**
     * The object's members as `decodeObject()` reads them, with every number a
     * number.
     *
     * @param  string  $json
     * @return ?array<array-key, mixed>
     */
    public static function decodeMembers(#[\SensitiveParameter] string $json): ?array
    {
        /** @var ?array<array-key, mixed> */
        return self::decodeObject($json) === null ? null : self::decoded($json, true, JSON_THROW_ON_ERROR);
    }

    /**
     * The object as `decodeObject()` reads it, keeping objects distinct from
     * lists and every number a number.
     *
     * @param  string  $json
     * @return ?\stdClass
     */
    public static function decodeAsWritten(#[\SensitiveParameter] string $json): ?\stdClass
    {
        $written = self::decodeObject($json) === null ? null : self::decoded($json, false, JSON_THROW_ON_ERROR);

        return $written instanceof \stdClass ? $written : null;
    }

    /**
     * Decode the text, or return `null` when it cannot be.
     *
     * @param  string  $json
     * @param  bool  $associative
     * @param  int  $flags
     * @return mixed
     */
    private static function decoded(#[\SensitiveParameter] string $json, bool $associative = true, int $flags = self::DIGITS): mixed
    {
        try {
            return json_decode($json, $associative, self::MAX_DEPTH, $flags);
        } catch (\JsonException) {
            return null;
        }
    }

    /**
     * Whether any object in the valid JSON text repeats a member name; a PCRE
     * failure counts as a repeat, so it fails closed.
     *
     * @param  string  $json
     * @return bool
     */
    private static function mayRepeatMember(#[\SensitiveParameter] string $json): bool
    {
        if (preg_match_all(self::TOKENS, $json, $matches) === false) {
            return true;
        }

        $tokens = $matches[0];
        $open   = new OpenContainers;

        foreach ($tokens as $index => $token) {

            self::track($open, $token);

            if (($tokens[$index + 1] ?? null) === ':' && self::isRepeated($open->top(), $token)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Push or pop a container for a bracket token.
     *
     * @param  \SplStack<\ArrayObject<string, string>>  $open
     * @param  string  $token
     * @return void
     */
    private static function track(\SplStack $open, string $token): void
    {
        if ($token === '{' || $token === '[') {
            $open->push(new \ArrayObject);
        }

        if ($token !== '}' && $token !== ']') {
            return;
        }

        $open->pop();
    }

    /**
     * Whether the decoded name was already seen in its object, recording it.
     *
     * @param  \ArrayObject<string, string>  $seen
     * @param  string  $literal
     * @return bool
     */
    private static function isRepeated(\ArrayObject $seen, string $literal): bool
    {
        $name = json_decode($literal);
        $name = is_string($name) ? $name : $literal;

        if ($seen->offsetExists($name)) {
            return true;
        }

        $seen->offsetSet($name, $name);

        return false;
    }
}
