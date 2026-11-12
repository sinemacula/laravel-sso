<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

/**
 * Redacts the whole value under a redacted key in a JSON member, an XML element
 * or a pair, reading each value to where its form ends it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeyedValues
{
    /** @var string The namespace prefix an XML name may carry, as in `saml:`. */
    private const string PREFIX = '(?:[A-Za-z_][\w.\-]*:)?';

    /** @var string A JSON member's key and colon, at any escape level. */
    private const string JSON_KEYS = '/(?<!\\\)(\\\*)"([^"]{0,127}[^"\\\])\1"\s*:\s*/u';

    /** @var string A bare JSON value: up to the `,`, `}` or `]` that ends it. */
    private const string BARE_JSON_VALUES = '/\G[^,}\]]*+/u';

    /** @var string An XML opening tag, self-closing or not. */
    private const string OPENING_TAGS = '/<(' . self::PREFIX . '([A-Za-z_][\w.\-]*))(?=[\s\/>])([^<>]*?)(\/?)>/u';

    /** @var string A tag cut short by the length cap, at the end of the text. */
    private const string CUT_TAGS = '/<\/?([^<>]*)' . DiagnosticSanitizer::ELLIPSIS . '\z/u';

    /** @var string A pair's key, bare, quoted or bracketed, and its separator. */
    private const string PAIR_KEYS = '/(?<![\w.\-%+])(\\\*["\']|\[)?' . self::PREFIX . '([\w.\-%+]+(?:\[[^\[\]\s=&]*\])*)(?:\\\*["\']|\])?\s*(=>?|:(?!\/\/))\s*/u';

    /** @var string An `&` starting another pair, or one cut by the length cap. */
    private const string PAIR_STARTS = '/\G&(?:[\w.\-%+:\[\]]+=|[\w.\-%+:\[\]]*' . DiagnosticSanitizer::ELLIPSIS . '\z)/u';

    /** @var list<string> Credential headers, whose value runs to the end of the text. */
    private const array CREDENTIAL_HEADERS = ['authorization', 'proxyauthorization', 'cookie', 'setcookie'];

    /** @var array<string, string> Brackets an unquoted value is read through. */
    private const array BRACKETS = ['(' => ')', '[' => ']', '{' => '}'];

    /** @var string The whitespace that ends an unquoted value. */
    private const string WHITESPACE = " \t\n\r\x0B\f";

    /** @var string A quote or backslash at another escape level. */
    private const string OTHER = '.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Redact every keyed value; `null` on a PCRE failure.
     *
     * @param  string  $text
     * @param  \SineMacula\Laravel\Sso\Logging\RedactedKeys  $keys
     * @return ?string
     */
    public static function redact(string $text, RedactedKeys $keys): ?string
    {
        $text = self::replace(
            $text,
            self::JSON_KEYS,
            static fn (array $match, string $text, int $start): ?array => self::jsonMember($match, $text, $start, $keys),
        );

        $text = $text === null ? null : self::replace(
            $text,
            self::OPENING_TAGS,
            static fn (array $match, string $text, int $start): ?array => self::element($match, $text, $start, $keys),
        );

        return $text === null ? null : self::replace(
            $text,
            self::PAIR_KEYS,
            static fn (array $match, string $text, int $start): ?array => self::pair($match, $text, $start, $keys),
        );
    }

    /**
     * Replace the span the callback returns after each match, keeping a
     * trailing ellipsis; `null` on a PCRE failure.
     *
     * @param  string  $text
     * @param  string  $pattern
     * @param  \Closure(array<array-key, array{0: string, 1: int}>, string, int): ?array{0: int, 1: int, 2: string}  $value
     * @return ?string
     */
    private static function replace(string $text, string $pattern, \Closure $value): ?string
    {
        $found = preg_match($pattern, $text, $match, PREG_OFFSET_CAPTURE);

        while ($found === 1) {

            $offset      = $match[0][1] + strlen($match[0][0]);
            $replacement = $value($match, $text, $offset);

            if ($replacement !== null && $replacement[1] > $replacement[0]) {

                [$from, $to, $with] = $replacement;

                $with .= $to === strlen($text) && str_ends_with($text, DiagnosticSanitizer::ELLIPSIS) ? DiagnosticSanitizer::ELLIPSIS : '';
                $text   = substr_replace($text, $with, $from, $to - $from);
                $offset = $from + strlen($with);
            }

            $found = preg_match($pattern, $text, $match, PREG_OFFSET_CAPTURE, $offset);
        }

        return $found === false ? null : $text;
    }

    /**
     * The JSON member's value span and replacement, when its key is redacted.
     *
     * @param  array<array-key, array{0: string, 1: int}>  $match
     * @param  string  $text
     * @param  int  $start
     * @param  \SineMacula\Laravel\Sso\Logging\RedactedKeys  $keys
     * @return ?array{0: int, 1: int, 2: string}
     */
    private static function jsonMember(array $match, string $text, int $start, RedactedKeys $keys): ?array
    {
        $level = strlen($match[1][0]);

        if (!$keys->matches(self::jsonKey($match[2][0], $level))) {
            return null;
        }

        $quote = $match[1][0] . '"';

        return [$start, self::jsonValueEnd($text, $start, $level), $quote . DiagnosticSanitizer::REDACTED . $quote];
    }

    /**
     * The element's content span, or a self-closing one's attributes, when its
     * unprefixed name is redacted.
     *
     * @param  array<array-key, array{0: string, 1: int}>  $match
     * @param  string  $text
     * @param  int  $start
     * @param  \SineMacula\Laravel\Sso\Logging\RedactedKeys  $keys
     * @return ?array{0: int, 1: int, 2: string}
     */
    private static function element(array $match, string $text, int $start, RedactedKeys $keys): ?array
    {
        if (!$keys->matches($match[2][0])) {
            return null;
        }

        if ($match[4][0] === '') {
            return [$start, self::elementEnd($text, $start, $match[1][0]), DiagnosticSanitizer::REDACTED];
        }

        $attributes = $match[3];

        return trim($attributes[0]) === '' ? null : [$attributes[1], $attributes[1] + strlen($attributes[0]), ' ' . DiagnosticSanitizer::REDACTED];
    }

    /**
     * The pair's value span and replacement, when its key is redacted; a
     * double-quoted key before `:` is left to `jsonMember()`.
     *
     * @param  array<array-key, array{0: string, 1: int}>  $match
     * @param  string  $text
     * @param  int  $start
     * @param  \SineMacula\Laravel\Sso\Logging\RedactedKeys  $keys
     * @return ?array{0: int, 1: int, 2: string}
     */
    private static function pair(array $match, string $text, int $start, RedactedKeys $keys): ?array
    {
        [$key, $at] = $match[2];
        $colon      = $match[3][0] === ':';
        $level      = strspn($text, '\\', $start);
        $quote      = $text[$start + $level] ?? '';
        $wrap       = substr($text, $start, $level + 1);
        $header     = $colon && in_array(LoggingSettings::normalizeKey(rawurldecode($key)), self::CREDENTIAL_HEADERS, true);

        $skipped = ($colon && str_contains($match[1][0], '"'))
            || ($level > 0 && substr($text, $start + $level) === DiagnosticSanitizer::ELLIPSIS)
            || !$keys->matchesAfter(substr($text, 0, $at), $key);

        return match (true) {
            $skipped                          => null,
            $header                           => [$start, strlen($text), DiagnosticSanitizer::REDACTED],
            $quote === '"' || $quote === '\'' => [$start, self::quotedEnd($text, $start, $level, $quote), $wrap . DiagnosticSanitizer::REDACTED . $wrap],
            default                           => [$start, self::unquotedEnd($text, $start), DiagnosticSanitizer::REDACTED],
        };
    }

    /**
     * Unescape the key once per enclosing JSON string, then decode it.
     *
     * @param  string  $key
     * @param  int  $level
     * @return string
     */
    private static function jsonKey(string $key, int $level): string
    {
        for ($pass = $level === 0 ? 0 : strlen(decbin($level)); $pass > 0; $pass--) {
            $key = preg_replace('/\\\(.)/su', '$1', $key) ?? $key;
        }

        $decoded = json_decode('"' . $key . '"');

        return is_string($decoded) ? $decoded : $key;
    }

    /**
     * Where the JSON value starting at the offset ends.
     *
     * @param  string  $text
     * @param  int  $at
     * @param  int  $level
     * @return int
     */
    private static function jsonValueEnd(string $text, int $at, int $level): int
    {
        return match (self::token($text, $at, $level)[0]) {
            '"'      => self::quotedEnd($text, $at, $level, '"'),
            '{', '[' => self::jsonContainerEnd($text, $at, $level),
            default  => $at + strlen(rtrim(substr($text, $at, self::end(self::BARE_JSON_VALUES, $text, $at) - $at), ' ')),
        };
    }

    /**
     * Where the JSON object or array opened at the offset ends.
     *
     * @param  string  $text
     * @param  int  $at
     * @param  int  $level
     * @return int
     */
    private static function jsonContainerEnd(string $text, int $at, int $level): int
    {
        $length = strlen($text);
        $depth  = 0;

        while ($at < $length) {

            [$token, $next] = self::token($text, $at, $level);

            $depth += match ($token) {
                '{', '[' => 1,
                '}', ']' => -1,
                default  => 0,
            };

            if ($depth === 0) {
                return $next;
            }

            $at = $token === '"' ? self::quotedEnd($text, $at, $level, '"') : $next;
        }

        return $length;
    }

    /**
     * Where the string opened at the offset ends, at the same escape level.
     *
     * @param  string  $text
     * @param  int  $at
     * @param  int  $level
     * @param  string  $quote
     * @return int
     */
    private static function quotedEnd(string $text, int $at, int $level, string $quote): int
    {
        $length = strlen($text);
        $at     = self::token($text, $at, $level)[1];

        while ($at < $length) {

            [$token, $next] = self::token($text, $at, $level);

            if ($token === $quote) {
                return $next;
            }

            $at = $token === '\\' ? self::token($text, $next, $level)[1] : $next;
        }

        return $length;
    }

    /**
     * Where the unquoted value ends, reading through any quotes and brackets.
     *
     * @param  string  $text
     * @param  int  $at
     * @return int
     */
    private static function unquotedEnd(string $text, int $at): int
    {
        $length  = strlen($text);
        $closing = [];

        while ($at < $length) {

            if ($closing === [] && self::endsUnquoted($text, $at)) {
                return $at;
            }

            $level   = strspn($text, '\\', $at);
            $quote   = $text[$at + $level] ?? '';
            $closing = self::closingAfter($closing, $text[$at]);
            $at      = $quote === '"' || $quote === '\'' ? self::quotedEnd($text, $at, $level, $quote) : $at + max($level, 1);
        }

        return $length;
    }

    /**
     * Whether whitespace or an `&` starting another pair is at the offset.
     *
     * @param  string  $text
     * @param  int  $at
     * @return bool
     */
    private static function endsUnquoted(string $text, int $at): bool
    {
        $char = $text[$at] ?? '';

        return str_contains(self::WHITESPACE, $char) || ($char === '&' && preg_match(self::PAIR_STARTS, $text, $match, 0, $at) === 1);
    }

    /**
     * The closing brackets still awaited once the character is read.
     *
     * @param  list<string>  $closing
     * @param  string  $char
     * @return list<string>
     */
    private static function closingAfter(array $closing, string $char): array
    {
        if (isset(self::BRACKETS[$char])) {
            return [...$closing, self::BRACKETS[$char]];
        }

        return $closing !== [] && $char === $closing[count($closing) - 1] ? array_slice($closing, 0, -1) : $closing;
    }

    /**
     * The token at the offset and the offset after it; `$level` is the number
     * of backslashes a quote carries (`1` inside a JSON string).
     *
     * @param  string  $text
     * @param  int  $at
     * @param  int  $level
     * @return array{0: string, 1: int}
     */
    private static function token(string $text, int $at, int $level): array
    {
        $char = $text[$at] ?? '';

        if ($char === '') {
            return ['', $at];
        }

        $run = strspn($text, '\\', $at);

        if ($run > $level) {
            return ['\\', $at + $level + 1];
        }

        $after = $text[$at + $run] ?? '';
        $quote = $after === '"' || $after === '\'';

        return match (true) {
            $quote && $run === $level => [$after, $at + $run + 1],
            $quote || $run > 0        => [self::OTHER, $at + max($run, 1)],
            default                   => [$char, $at + 1],
        };
    }

    /**
     * Where the named element's content ends, counting nested same-name tags.
     *
     * @param  string  $text
     * @param  int  $at
     * @param  string  $name
     * @return int
     */
    private static function elementEnd(string $text, int $at, string $name): int
    {
        $pattern = '/<(\/?)' . preg_quote($name, '/') . '(?=[\s\/>])[^<>]*?(\/?)>/u';
        $from    = $at;
        $depth   = 1;

        while (preg_match($pattern, $text, $match, PREG_OFFSET_CAPTURE, $at) === 1) {

            $depth += $match[1][0] === '/' ? -1 : (int) ($match[2][0] === '');

            if ($depth === 0) {
                return $match[0][1];
            }

            $at = $match[0][1] + strlen($match[0][0]);
        }

        $cut = preg_match(self::CUT_TAGS, $text, $match, PREG_OFFSET_CAPTURE, $from) === 1 && str_starts_with($name, $match[1][0]);

        return $cut ? $match[0][1] : strlen($text);
    }

    /**
     * Where the anchored match ends, or the end of the text on failure.
     *
     * @param  string  $pattern
     * @param  string  $text
     * @param  int  $at
     * @return int
     */
    private static function end(string $pattern, string $text, int $at): int
    {
        return preg_match($pattern, $text, $match, 0, $at) === 1 ? $at + strlen($match[0]) : strlen($text);
    }
}
