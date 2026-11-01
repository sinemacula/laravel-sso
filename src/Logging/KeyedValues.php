<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

/**
 * Redacts the whole value under a redacted key in diagnostic text, whatever the
 * value holds, in a JSON member, an XML element and a pair (SSO-5.7, SSO-9.8,
 * SSO-11.9).
 *
 * Each form is found by its key, and its value is then read to where that form
 * ends it, never to the first punctuation it holds:
 *
 * - a JSON member (`"key": value`, plain or escaped inside a JSON string any
 *   number of times): a string to its closing quote, an object or array to its
 *   closing bracket, strings within it skipped, and a number, boolean, `null`
 *   or anything else to the `,`, `}` or `]` that ends it. Its key's escapes are
 *   undone and its JSON escapes decoded (`\u005f` is `_`), and the value
 *   becomes `"[redacted]"`, quoted as the member's key is;
 * - an XML element (`<key>…</key>`, with any namespace prefix and attributes):
 *   its content, child elements included, to its matching closing tag; a
 *   self-closing one (`<key a="…"/>`) has its attributes redacted instead;
 * - a pair, its key bare, quoted (`'key'`) or in brackets (`[key]`), and its
 *   separator `=`, `=>` or `:`, as in a query string, a form, an XML attribute,
 *   a PHP array dump, YAML or a header: a quoted value, its quotes escaped any
 *   number of times (`\"…\"` inside a JSON string), to its closing quote, a
 *   backslash escaping the next character; an unquoted one to the next space or
 *   to the next `&` that starts another pair, but read through any quotes and
 *   brackets it holds (`[…]`, `{…}`, `(…)`), spaces within them included, so
 *   `,`, `;`, `=`, quotes, brackets and an `&` that starts no pair are all part
 *   of it. A header that is itself a credential (`Authorization:`,
 *   `Proxy-Authorization:`, `Cookie:`, `Set-Cookie:`) has its value read to the
 *   end of the text, every parameter of it included. Its key may be percent- or
 *   plus-encoded, carry a form's brackets, and be named by the words just
 *   before it (`private key=…`; see `RedactedKeys`). A double-quoted key before
 *   a `:` is a JSON member's, left to the JSON rule.
 *
 * A value cut short, without its closing quote, bracket or tag, runs to the end
 * of the text. One that ends the text in `…`, as the length cap leaves it, is
 * replaced with `[redacted]` and its closing quote followed by `…`, so
 * sanitising cut text again, which caps it again, changes nothing. A key, an
 * empty value and everything around the value are kept, and a value under any
 * other key is still searched, so a member nested in an innocent one is found.
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

    /** @var string A JSON member's key and colon, its quotes escaped as many times as it sits in nested JSON strings. */
    private const string JSON_KEYS = '/(?<!\\\)(\\\*)"([^"]{0,127}[^"\\\])\1"\s*:\s*/u';

    /** @var string A bare JSON value: up to the `,`, `}` or `]` that ends it. */
    private const string BARE_JSON_VALUES = '/\G[^,}\]]*+/u';

    /** @var string An XML element's opening tag, self-closing or not, with any namespace prefix and attributes. */
    private const string OPENING_TAGS = '/<(' . self::PREFIX . '([A-Za-z_][\w.\-]*))(?=[\s\/>])([^<>]*?)(\/?)>/u';

    /** @var string A tag cut short by the length cap, at the end of the text. */
    private const string CUT_TAGS = '/<\/?([^<>]*)' . DiagnosticSanitizer::ELLIPSIS . '\z/u';

    /** @var string A pair's key, bare, quoted or in brackets, and its separator, the key with any namespace prefix, percent- or plus-encoding and a form's brackets. */
    private const string PAIR_KEYS = '/(?<![\w.\-%+])(\\\*["\']|\[)?' . self::PREFIX . '([\w.\-%+]+(?:\[[^\[\]\s=&]*\])*)(?:\\\*["\']|\])?\s*(=>?|:(?!\/\/))\s*/u';

    /** @var string An `&` that starts another pair in a query string, or one cut short by the length cap. */
    private const string PAIR_STARTS = '/\G&(?:[\w.\-%+:\[\]]+=|[\w.\-%+:\[\]]*' . DiagnosticSanitizer::ELLIPSIS . '\z)/u';

    /** @var list<string> The normalised names of the headers that are themselves credentials, whose value runs to the end of the text. */
    private const array CREDENTIAL_HEADERS = ['authorization', 'proxyauthorization', 'cookie', 'setcookie'];

    /** @var array<string, string> The brackets an unquoted value is read through, each with its closing bracket. */
    private const array BRACKETS = ['(' => ')', '[' => ']', '{' => '}'];

    /** @var string The whitespace that ends an unquoted value. */
    private const string WHITESPACE = " \t\n\r\x0B\f";

    /** @var string The token of a character with no meaning in the form being read: a quote or backslash at another escape level. */
    private const string OTHER = '.';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The text with the value under every redacted key in a JSON member, an XML
     * element and a pair replaced, or `null` when a pattern could not run over
     * it (a PCRE limit).
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
     * The text with what follows each match of the pattern replaced as the
     * callback says, given the match, the text and the offset after the match:
     * from the offset it gives to the offset it gives, with the replacement it
     * gives, or not at all when it gives `null` or an empty span. A span that
     * ends the text in `…` (cut by the length cap) is replaced with the
     * replacement followed by `…`. The search goes on after the replacement, or
     * after the match when nothing is replaced. `null` when the pattern could
     * not run.
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
     * The span of the JSON member's value and what it is replaced with, when
     * its key is a redacted key.
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
     * The span of the XML element's content and what it is replaced with, when
     * its name, without any namespace prefix, is a redacted key; or, when it is
     * self-closing, the span of its attributes, if it has any.
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
     * The span of the pair's value and what it is replaced with, when its key,
     * or the words just before it run on into it, is a redacted key: a quoted
     * value keeps its quotes, escaped as they are, and a credential header's
     * value runs to the end of the text. A double-quoted key before a `:` is a
     * JSON member's, left to `jsonMember()`, and a value of nothing but the
     * backslashes of a quote the length cap cut off holds nothing to redact.
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
     * The JSON key, its escaping undone: a key escaped at the level given (the
     * number of backslashes before its quotes) is unescaped once for each
     * string it sits in, then any JSON escape is decoded. A key that does not
     * decode is kept as found.
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
     * Where the JSON value starting at the offset ends: after its closing quote
     * or bracket, or before the `,`, `}` or `]` that ends a bare value (and the
     * spaces before it).
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
     * Where the JSON object or array whose opening bracket is at the offset
     * ends: after its matching closing bracket, strings within it skipped, or
     * at the end of the text when it is cut short.
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
     * Where the string whose opening quote, escaped at the level given, is at
     * the offset ends: after its closing quote at the same level, an escaping
     * backslash skipping the next token, or at the end of the text when it is
     * cut short.
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
     * Where the unquoted pair value starting at the offset ends: at the next
     * whitespace or `&` that starts another pair, outside any quotes and
     * brackets it holds, or at the end of the text when one of those is cut
     * short. A quote, escaped any number of times, starts a string at that
     * level.
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
     * Whether an unquoted value outside any bracket ends at the offset: at
     * whitespace, or at an `&` that starts another pair.
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
     * The closing brackets still awaited once the character is read: one more
     * after an opening bracket, one fewer after the closing bracket awaited
     * last, and the same after anything else.
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
     * The token at the offset, read at the escape level given (the number of
     * backslashes a quote carries there: `0` in plain text, `1` inside a JSON
     * string, `3` inside one nested in another), and the offset after it: an
     * escaping backslash (`\` doubled once for each level) is `\`, a quote with
     * exactly the level's backslashes is the quote, a backslash or quote that
     * is neither is `OTHER`, any other character is itself, and the end of the
     * text is empty.
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
     * Where the content of the named element, starting at the offset, ends: at
     * its matching closing tag, elements of the same name within it counted, at
     * a tag cut short by the length cap that could be its closing tag, or at
     * the end of the text when it is otherwise cut short.
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
     * Where the match of the pattern, anchored at the offset, ends, or the end
     * of the text when the pattern could not run.
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
