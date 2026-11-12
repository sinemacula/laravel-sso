<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

/**
 * Turns uncontrolled text into bounded, single-line log text with secrets
 * redacted, erring towards removing too much. Idempotent.
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

    /** @var string C0, DEL, C1 and Unicode bidirectional controls. */
    private const string CONTROLS = '/[\x{00}-\x{1F}\x{7F}-\x{9F}\x{061C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';

    /** @var string A PEM block, or one cut before its end. */
    private const string PEM = '/-----BEGIN [A-Z0-9 ]{1,64}-----.*?(?:-----END [A-Z0-9 ]{1,64}-----|\z)/su';

    /** @var string The namespace prefix an XML name may carry, as in `saml:`. */
    private const string PREFIX = '(?:[A-Za-z_][\w.\-]*:)?';

    /** @var string The SAML elements whose content is a secret. */
    private const string SECRET_NAMES = '(?:Assertion|EncryptedAssertion|SignatureValue|X509Certificate)';

    /** @var string A secret SAML element, whole, including one cut short. */
    private const string SECRET_ELEMENTS = '/<(' . self::PREFIX . self::SECRET_NAMES . ')(?=[\s\/>])[^>]*?(?:\/>|>.*?(?:<\/\1\s*>|\z))/su';

    /** @var string A JWS or JWT (three parts) or a JWE (five). */
    private const string JWTS = '/eyJ[A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]*){2,4}/u';

    /** @var string The credential of a `Bearer` or `Basic` authorisation. */
    private const string SCHEMES = '/\b(Bearer|Basic)(\s+)[A-Za-z0-9\-._~+\/]+=*/iu';

    /** @var string 40 or more base64 characters: secrets under no known name. */
    private const string LONG_RUNS = '/[A-Za-z0-9+\/_\-]{40,}={0,2}/u';

    /** @var string A space-delimited run holding percent or HTML entity encoding. */
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
     * Sanitise the text.
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
     * Strip controls and collapse whitespace before redacting, so every pattern
     * sees the same text; `null` on a PCRE failure.
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
     * Replace every secret; `null` on a PCRE failure.
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
     * The run, or `[redacted]` when its decoded text, with `+` either way,
     * carries a secret.
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
     * Undo percent and HTML entity encoding repeatedly; `null` if still encoded
     * after `RedactedKeys::MAX_DECODES` passes.
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
     * Cut to exactly the length, ending in the ellipsis, so re-runs are no-ops.
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
