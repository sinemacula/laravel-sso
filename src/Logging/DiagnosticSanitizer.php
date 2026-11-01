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
 * controls are removed, so a diagnostic cannot forge a log line or reorder what
 * a reader sees; whitespace is collapsed to single spaces and trimmed; secrets
 * are replaced with `[redacted]`; and the text is cut to
 * `sso.logging.max_diagnostic_length` characters, ending in `…` when cut.
 * Whitespace is collapsed before redaction rather than after, so a pattern sees
 * the same text on every pass and an unusual space cannot hide a secret from
 * it; a redaction never leaves two spaces together, so the result is the same.
 * A pattern that cannot run over the text (a PCRE limit) redacts the text
 * whole.
 *
 * What is redacted: a JWS, JWT or JWE; the credential after `Bearer` or
 * `Basic`; a PEM block; a SAML `Assertion`, `EncryptedAssertion`,
 * `SignatureValue` or `X509Certificate` element, whole; the whole value, of
 * whatever type and punctuation, of a pair (`key=value`, `key="value"`, `key =>
 * value`, `key: value`, an XML attribute, a credential header to the end of the
 * text), a JSON `"key": value` member (escaped JSON too) and an XML element
 * whose key, decoded, is a redacted key (see `KeyedValues` and `RedactedKeys`);
 * any run of 40 or more base64 or base64url characters, which catches
 * assertions, codes, tokens and keys under no recognisable name; and any
 * percent- or HTML-entity-encoded run of text that, decoded, carries any of
 * these. Redaction errs towards removing too much: a long identifier or path is
 * redacted with the secrets, a value cut short is redacted to the end of the
 * text, and an encoded URL that carries a secret is redacted whole.
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

    /** @var string A run of 40 or more base64 or base64url characters, with any padding. */
    private const string LONG_RUNS = '/[A-Za-z0-9+\/_\-]{40,}={0,2}/u';

    /** @var string A run of text holding a percent-encoded byte or an HTML character reference, from one space to the next. */
    private const string ENCODED_RUNS = '/(?<!\S)(?=\S*?(?:%[0-9A-Fa-f]{2}|&(?:#[0-9]+|#[Xx][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);))\S++/u';

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
        $text = self::clean(mb_scrub($text, 'UTF-8'), RedactedKeys::from($this->settings)) ?? self::REDACTED;

        return self::cap($text, $this->settings->maxDiagnosticLength());
    }

    /**
     * The text with tabs and line breaks as spaces, every other control removed
     * and whitespace collapsed, then with every secret replaced (see
     * `redact()`), and trimmed. `null` when a pattern could not run over the
     * text (a PCRE limit), which the caller answers by redacting the text whole
     * rather than logging it unsanitised.
     *
     * @param  string  $text
     * @param  \SineMacula\Laravel\Sso\Logging\RedactedKeys  $keys
     * @return ?string
     */
    private static function clean(string $text, RedactedKeys $keys): ?string
    {
        $text = preg_replace([self::BREAKS, self::CONTROLS, self::WHITESPACE], [' ', '', ' '], $text);
        $text = $text === null ? null : self::redact($text, $keys);

        return $text === null ? null : trim($text);
    }

    /**
     * The text with every secret replaced: whole blocks and elements first,
     * then credentials, then values by their key (`KeyedValues`), then long
     * runs, then any percent- or entity-encoded run that, decoded, carries a
     * secret. `null` when a pattern could not run over the text.
     *
     * @param  string  $text
     * @param  \SineMacula\Laravel\Sso\Logging\RedactedKeys  $keys
     * @return ?string
     */
    private static function redact(string $text, RedactedKeys $keys): ?string
    {
        $text = preg_replace(
            [self::PEM, self::SECRET_ELEMENTS, self::JWTS, self::SCHEMES],
            [self::REDACTED, self::REDACTED, self::REDACTED, '$1$2' . self::REDACTED],
            $text,
        );

        $text = $text === null ? null : KeyedValues::redact($text, $keys);
        $text = $text === null ? null : preg_replace(self::LONG_RUNS, self::REDACTED, $text);

        return $text === null ? null : preg_replace_callback(self::ENCODED_RUNS, static fn (array $match): string => self::redactEncodedRun($match[0], $keys), $text);
    }

    /**
     * The encoded run, or `[redacted]` when, decoded, it carries a secret:
     * redacting its decoded text, with `+` kept or read as a space, would
     * change it. A run still encoded after `RedactedKeys::MAX_DECODES` passes
     * is taken to carry one.
     *
     * @param  string  $run
     * @param  \SineMacula\Laravel\Sso\Logging\RedactedKeys  $keys
     * @return string
     */
    private static function redactEncodedRun(string $run, RedactedKeys $keys): string
    {
        $decoded = self::decode($run);

        if ($decoded === null) {
            return self::REDACTED;
        }

        foreach ([$decoded, strtr($decoded, '+', ' ')] as $view) {
            if (self::redact($view, $keys) !== $view) {
                return self::REDACTED;
            }
        }

        return $run;
    }

    /**
     * The run with its percent-encoding and HTML character references (`&#61;`,
     * `&quot;`) undone until nothing is left to undo, invalid UTF-8 scrubbed,
     * or `null` when something still is after `RedactedKeys::MAX_DECODES`
     * passes.
     *
     * @param  string  $run
     * @return ?string
     */
    private static function decode(string $run): ?string
    {
        for ($pass = 0; $pass <= RedactedKeys::MAX_DECODES; $pass++) {

            $decoded = html_entity_decode(rawurldecode($run), ENT_QUOTES | ENT_HTML5, 'UTF-8');

            if ($decoded === $run) {
                return mb_scrub($run, 'UTF-8');
            }

            $run = $decoded;
        }

        return null;
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
