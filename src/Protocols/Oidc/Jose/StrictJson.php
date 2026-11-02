<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * The strict JSON decoder every JOSE value the package reads goes through
 * before anything else sees it (SSO-7.3, SSO-7.4): a JWT's header and payload,
 * a JWKS, a discovery document, a token response and a UserInfo response.
 *
 * `decodeObject()` answers the members of a JSON object, or `null` when the
 * text is not one: not valid JSON (invalid UTF-8 included), not an object at
 * its top level, nested deeper than `MAX_DEPTH`, or holding a member name twice
 * in any object at any depth. Names are compared once their escapes are read,
 * so `"a"` and `"\u0061"` are the same name: PHP's decoder would keep the last
 * of two silently, and two readers of one document could disagree about it. An
 * integer too large for PHP's is kept as its digits, a string, so a numeric
 * date refuses it rather than reading a finite float; a string-typed reader
 * must not read that form, or it would take the number for its digits.
 *
 * `decodeMembers()` and `decodeAsWritten()` refuse exactly what
 * `decodeObject()` does, and keep what JSON wrote, so that a string-typed check
 * means a JSON string: in both, an integer too large for PHP's is a float.
 * `decodeAsWritten()` also keeps an object a `\stdClass` and a list an array,
 * which a PHP array would not tell apart (`{"0":"a"}` and `["a"]`), and refuses
 * a member name an object cannot hold. Whatever reads a string or a list of a
 * provider's document reads one of these two.
 *
 * It holds nothing between calls (SSO-11.2).
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
     * The members of the JSON object the text holds, or `null` when it holds
     * anything else, is malformed or repeats a member name.
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

        return self::hasRepeatedMember($json) ? null : $decoded;
    }

    /**
     * The members of the JSON object the text holds, as `decodeObject()` reads
     * and refuses them, with every number a number: never its digits.
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
     * The JSON object the text holds, as `decodeObject()` reads and refuses it,
     * with what JSON wrote kept: an object a `\stdClass`, a list an array, and
     * every number a number. A member name an object cannot hold is refused.
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
     * The text decoded, with objects as asked and the flags given, or `null`
     * when it cannot be.
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
     * Whether any object in the valid JSON text names a member twice, its names
     * compared once their escapes are read.
     *
     * The text is valid JSON, so its strings and structural characters are read
     * as tokens in order, and a member name is a string followed by `:`. Each
     * open object and array keeps the names seen in it; an array never gains
     * one.
     *
     * @param  string  $json
     * @return bool
     */
    private static function hasRepeatedMember(#[\SensitiveParameter] string $json): bool
    {
        preg_match_all(self::TOKENS, $json, $matches);

        $tokens = $matches[0];
        $open   = new \SplStack;

        foreach ($tokens as $index => $token) {

            self::track($open, $token);

            if (($tokens[$index + 1] ?? null) === ':' && self::isRepeated($open->top(), $token)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Open or close a container on the stack of open ones, for a token that
     * does; a container opens with no name seen in it yet.
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
     * Whether the member name the string literal writes was seen before in its
     * object, which then records it.
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
