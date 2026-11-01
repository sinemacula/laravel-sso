<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

/**
 * Redacts a log call's context before it reaches a channel (SSO-9.8, SSO-11.9).
 *
 * A value under a redacted key (`LoggingSettings::redactedKeys()`: the built-in
 * `REDACTED_KEYS` plus any configured, matched decoded and normalised, as the
 * sanitiser matches them; see `RedactedKeys`) is `[redacted]`, whatever it
 * holds, an array or an object included. Every other string is sanitised as a
 * diagnostic (`DiagnosticSanitizer`), so a secret under an innocent key is
 * still caught by its shape. Integers, floats, booleans and `null` are kept,
 * and a backed enum is its value.
 *
 * Objects are never dumped, cast or serialised, so nothing a value object keeps
 * private (a request's form, a result's body, a secret) can reach a log: a
 * `Throwable` is reduced to its class, its sanitised message and its code,
 * without its trace or previous exceptions; any other object is
 * `[object <class>]`. Arrays are followed to a depth of `MAX_DEPTH`, the
 * context itself the first; an array deeper than that is `[truncated]`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Redactor
{
    /** @var list<string> The keys always redacted, compared normalised (see `LoggingSettings::normalizeKey()`): secrets, verifiers, codes, protocol state, assertions, provider tokens and transport credentials. */
    public const array REDACTED_KEYS = [
        'password',
        'secret',
        'client_secret',
        'clientsecret',
        'token',
        'access_token',
        'refresh_token',
        'id_token',
        'code',
        'handoff_code',
        'verifier',
        'code_verifier',
        'state',
        'relay_state',
        'relaystate',
        'nonce',
        'assertion',
        'saml_response',
        'samlresponse',
        'saml_request',
        'samlrequest',
        'private_key',
        'privatekey',
        'authorization',
        'cookie',
        'set_cookie',
        'client_assertion',
        'signature',
    ];

    /** @var int The deepest array followed, the context itself being the first. */
    public const int MAX_DEPTH = 8;

    /** @var string What an array deeper than `MAX_DEPTH` is replaced with. */
    public const string TRUNCATED = '[truncated]';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Logging\LoggingSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Logging\DiagnosticSanitizer  $sanitizer
     */
    public function __construct(

        /** The settings the redacted keys are read from. */
        private LoggingSettings $settings,

        /** The sanitiser every string and exception message goes through. */
        private DiagnosticSanitizer $sanitizer,
    ) {}

    /**
     * The context, redacted.
     *
     * @param  array<array-key, mixed>  $context
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public function redact(#[\SensitiveParameter] array $context): array
    {
        return $this->redactArray($context, RedactedKeys::from($this->settings), 1);
    }

    /**
     * The array, redacted, at the depth given.
     *
     * @param  array<array-key, mixed>  $values
     * @param  \SineMacula\Laravel\Sso\Logging\RedactedKeys  $keys
     * @param  int  $depth
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function redactArray(array $values, RedactedKeys $keys, int $depth): array
    {
        $redacted = [];

        foreach ($values as $key => $value) {
            $redacted[$key] = $keys->matches((string) $key)
                ? DiagnosticSanitizer::REDACTED
                : $this->redactValue($value, $keys, $depth);
        }

        return $redacted;
    }

    /**
     * The value, redacted, as found in an array at the depth given.
     *
     * @param  mixed  $value
     * @param  \SineMacula\Laravel\Sso\Logging\RedactedKeys  $keys
     * @param  int  $depth
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    private function redactValue(mixed $value, RedactedKeys $keys, int $depth): mixed
    {
        return match (true) {
            is_string($value)                  => $this->sanitizer->sanitize($value),
            is_scalar($value), $value === null => $value,
            is_array($value)                   => $depth < self::MAX_DEPTH ? $this->redactArray($value, $keys, $depth + 1) : self::TRUNCATED,
            $value instanceof \BackedEnum      => $value->value,
            $value instanceof \Throwable       => $this->reduceThrowable($value),
            is_object($value)                  => '[object ' . $value::class . ']',
            default                            => '[' . get_debug_type($value) . ']',
        };
    }

    /**
     * The exception's class, sanitised message and code, without its trace or
     * previous exceptions.
     *
     * @param  \Throwable  $throwable
     * @return array{class: class-string<\Throwable>, message: string, code: int|string}
     *
     * @throws \InvalidArgumentException
     */
    private function reduceThrowable(\Throwable $throwable): array
    {
        /** @var int|string $code */
        $code = $throwable->getCode();

        return [
            'class'   => $throwable::class,
            'message' => $this->sanitizer->sanitize($throwable->getMessage()),
            'code'    => is_string($code) ? $this->sanitizer->sanitize($code) : $code,
        ];
    }
}
