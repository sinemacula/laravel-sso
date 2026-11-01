<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

/**
 * Turns text the package does not control (an identity provider's error
 * description or status message, an exception's message, a URL) into bounded,
 * sanitised text a log may carry (SSO-5.7, SSO-9.8, SSO-11.9).
 *
 * In order: invalid UTF-8 is scrubbed; tabs and line breaks become spaces, and
 * every other C0 control, DEL, every C1 control and the Unicode bidirectional
 * controls are removed, so a diagnostic cannot forge a log line or reorder
 * what a reader sees; whitespace is collapsed to single spaces and trimmed;
 * secrets are replaced with `[redacted]`; and the text is cut to
 * `sso.logging.max_diagnostic_length` characters, ending in `…` when cut.
 * Whitespace is collapsed before redaction rather than after, so a pattern sees
 * the same text on every pass and an unusual space cannot hide a secret from
 * it; a redaction never leaves two spaces together, so the result is the same.
 * A pattern that cannot run over the text (a PCRE limit) redacts the text
 * whole.
 *
 * What is redacted: a JWS, JWT or JWE; the credential after `Bearer` or
 * `Basic`; a PEM block; a SAML `Assertion`, `EncryptedAssertion`,
 * `SignatureValue` or `X509Certificate` element, whole; the value of a
 * `key=value` pair, a quoted `key="value"` pair or XML attribute, a JSON
 * `"key": value` member (escaped JSON too) and a simple XML element whose key
 * is a redacted key (see `LoggingSettings::redactedKeys()`); and any run of 40
 * or more base64 or base64url characters, which catches assertions, codes,
 * tokens and keys under no recognisable name. Redaction errs towards removing
 * too much: a long identifier or path is redacted with the secrets.
 *
 * Sanitising is idempotent: sanitising sanitised text changes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DiagnosticSanitizer
{
    /** @var string What a secret is replaced with. */
    public const string REDACTED = '[redacted]';

    /** @var string What cut text ends with. */
    public const string ELLIPSIS = '…';

    /** @var string Tabs and line breaks, each of which becomes a space. */
    private const string BREAKS = '/[\t\n\x0B\f\r]/';

    /** @var string C0 controls, DEL, C1 controls and the Unicode bidirectional marks, embeddings, overrides and isolates. */
    private const string CONTROLS = '/[\x{00}-\x{1F}\x{7F}-\x{9F}\x{061C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';

    /** @var string A PEM block, or one cut before its end. */
    private const string PEM = '/-----BEGIN [A-Z0-9 ]{1,64}-----.*?(?:-----END [A-Z0-9 ]{1,64}-----|\z)/su';

    /** @var string The namespace prefix an XML name may carry, as in `saml:`. */
    private const string PREFIX = '(?:[A-Za-z_][\w.\-]*:)?';

    /** @var string The SAML elements whose content is a secret. */
    private const string SECRET_NAMES = '(?:Assertion|EncryptedAssertion|SignatureValue|X509Certificate)';

    /** @var string A SAML element whose content is a secret, whole, with any namespace prefix: self-closing, closed, or cut before its end. */
    private const string SECRET_ELEMENTS = '/<(' . self::PREFIX . self::SECRET_NAMES . ')(?=[\s\/>])[^>]*?(?:\/>|>.*?(?:<\/\1\s*>|\z))/su';

    /** @var string A JWS or JWT (three parts) or a JWE (five), each starting with an encoded JSON header. */
    private const string JWTS = '/eyJ[A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]*){2,4}/u';

    /** @var string The credential of a `Bearer` or `Basic` authorisation. */
    private const string SCHEMES = '/\b(Bearer|Basic)(\s+)[A-Za-z0-9\-._~+\/]+=*/iu';

    /** @var string A JSON member, or an escaped one inside a JSON string, whose value is a string, a number or a boolean. */
    private const string JSON_MEMBERS = '/(\\\?")([^"\\\]{1,128})\1(\s*:\s*)("(?:[^"\\\]|\\\.)*"|\\\"(?:(?!\\\").)*\\\"|-?\d[\d.eE+\-]*|true|false)/u';

    /** @var string An XML element with a name and text content only, with any namespace prefix and attributes. */
    private const string ELEMENTS = '/(<(' . self::PREFIX . '([A-Za-z_][\w.\-]*))(?:\s[^<>]*)?>)([^<]+)(<\/\2\s*>)/u';

    /** @var string A quoted `key="value"` or `key='value'` pair, an XML attribute among them. */
    private const string QUOTED_PAIRS = '/(?<![\w.\-:])(' . self::PREFIX . '([A-Za-z_][\w.\-]*))(\s*=\s*)(["\'])(.*?)\4/su';

    /** @var string An unquoted `key=value` pair, as in a query string or a form. */
    private const string PAIRS = '/(?<![\w.\-])([A-Za-z_][\w.\-]*)(\s*=\s*)([^\s&#"\'<>\[\](),;]+)/u';

    /** @var string A run of 40 or more base64 or base64url characters, with any padding. */
    private const string LONG_RUNS = '/[A-Za-z0-9+\/_\-]{40,}={0,2}/u';

    /** @var string Whitespace, Unicode separators among it. */
    private const string WHITESPACE = '/[\s\p{Z}]+/u';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Logging\LoggingSettings  $settings
     */
    public function __construct(

        /** The settings the length cap and redacted keys are read from. */
        private LoggingSettings $settings,
    ) {}

    /**
     * The text, sanitised.
     *
     * @param  string  $text
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function sanitize(#[\SensitiveParameter] string $text): string
    {
        $text = $this->clean(mb_scrub($text, 'UTF-8'), array_flip($this->settings->redactedKeys())) ?? self::REDACTED;

        return self::cap($text, $this->settings->maxDiagnosticLength());
    }

    /**
     * The text with tabs and line breaks as spaces, every other control removed
     * and whitespace collapsed, then with every secret replaced: whole blocks
     * and elements first, then credentials, then values by their key, then long
     * runs. `null` when a pattern could not run over the text (a PCRE limit),
     * which the caller answers by redacting the text whole rather than logging
     * it unsanitised.
     *
     * @param  string  $text
     * @param  array<string, int>  $keys
     * @return ?string
     */
    private function clean(string $text, array $keys): ?string
    {
        $text = preg_replace(
            [self::BREAKS, self::CONTROLS, self::WHITESPACE, self::PEM, self::SECRET_ELEMENTS, self::JWTS, self::SCHEMES],
            [' ', '', ' ', self::REDACTED, self::REDACTED, self::REDACTED, '$1$2' . self::REDACTED],
            $text,
        );

        $text = $text === null ? null : preg_replace_callback_array([
            self::JSON_MEMBERS => static fn (array $match): string => self::redactJsonMember($match, $keys),
            self::ELEMENTS     => static fn (array $match): string => self::redactElement($match, $keys),
            self::QUOTED_PAIRS => static fn (array $match): string => self::redactQuotedPair($match, $keys),
            self::PAIRS        => static fn (array $match): string => self::redactPair($match, $keys),
        ], $text);

        $text = $text === null ? null : preg_replace(self::LONG_RUNS, self::REDACTED, $text);

        return $text === null ? null : trim($text);
    }

    /**
     * The JSON member, its value redacted when its key is a redacted key. An
     * escaped member keeps its escaped quotes.
     *
     * @param  array<array-key, string>  $match
     * @param  array<string, int>  $keys
     * @return string
     */
    private static function redactJsonMember(array $match, array $keys): string
    {
        if (!self::redacts($match[2], $keys)) {
            return $match[0];
        }

        $quote = str_starts_with($match[4], '\\') ? '\"' : '"';

        return $match[1] . $match[2] . $match[1] . $match[3] . $quote . self::REDACTED . $quote;
    }

    /**
     * The XML element, its content redacted when its name is a redacted key.
     *
     * @param  array<array-key, string>  $match
     * @param  array<string, int>  $keys
     * @return string
     */
    private static function redactElement(array $match, array $keys): string
    {
        return self::redacts($match[3], $keys) ? $match[1] . self::REDACTED . $match[5] : $match[0];
    }

    /**
     * The quoted pair, its value redacted when its key is a redacted key.
     *
     * @param  array<array-key, string>  $match
     * @param  array<string, int>  $keys
     * @return string
     */
    private static function redactQuotedPair(array $match, array $keys): string
    {
        return self::redacts($match[2], $keys) ? $match[1] . $match[3] . $match[4] . self::REDACTED . $match[4] : $match[0];
    }

    /**
     * The unquoted pair, its value redacted when its key is a redacted key.
     *
     * @param  array<array-key, string>  $match
     * @param  array<string, int>  $keys
     * @return string
     */
    private static function redactPair(array $match, array $keys): string
    {
        return self::redacts($match[1], $keys) ? $match[1] . $match[2] . self::REDACTED : $match[0];
    }

    /**
     * Whether the key, normalised, is one of the redacted keys.
     *
     * @param  string  $key
     * @param  array<string, int>  $keys
     * @return bool
     */
    private static function redacts(string $key, array $keys): bool
    {
        return isset($keys[LoggingSettings::normalizeKey($key)]);
    }

    /**
     * The text cut to the length, the last character kept being `…` when it is
     * cut, so cut text is exactly the length and sanitising it again leaves it
     * alone.
     *
     * @param  string  $text
     * @param  int  $length
     * @return string
     */
    private static function cap(string $text, int $length): string
    {
        if (mb_strlen($text, 'UTF-8') <= $length) {
            return $text;
        }

        return mb_substr($text, 0, $length - 1, 'UTF-8') . self::ELLIPSIS;
    }
}
