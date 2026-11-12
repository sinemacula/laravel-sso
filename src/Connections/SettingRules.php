<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;

/**
 * Shared value checks, so every settings class and helper refuses alike; each
 * answers the first problem's code or `null`, and never throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SettingRules
{
    /** @var int The longest URL accepted, in bytes. */
    public const int MAX_URL_LENGTH = 2048;

    /** @var string A control character: C0, DEL or C1. */
    private const string CONTROL = '/\p{Cc}/u';

    /** @var string Any whitespace. */
    private const string WHITESPACE = '/[\s\p{Z}]/u';

    /** @var string The start of a URL with an authority: a scheme, then `://`. */
    private const string AUTHORITY = '#^[A-Za-z][A-Za-z0-9+.-]*://#';

    /** @var string A URL's host: a bracketed IP literal or dotted DNS labels. */
    private const string HOST = '/^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*)$/D';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A non-empty, bounded UTF-8 string with no control character and, unless
     * allowed, no whitespace.
     *
     * @param  mixed  $value
     * @param  int  $maxBytes
     * @param  bool  $whitespace
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    public static function text(#[\SensitiveParameter] mixed $value, int $maxBytes, bool $whitespace = true): ?ViolationCode
    {
        if (!is_string($value)) {
            return ViolationCode::INVALID_TYPE;
        }

        $printable = self::isPrintable($value) && ($whitespace || preg_match(self::WHITESPACE, $value) !== 1);

        return match (true) {
            $value === ''              => ViolationCode::REQUIRED,
            strlen($value) > $maxBytes => ViolationCode::TOO_LONG,
            !$printable                => ViolationCode::INVALID_FORMAT,
            default                    => null,
        };
    }

    /**
     * An absolute `https` URL with a host, no userinfo and no fragment, and a
     * query only when allowed.
     *
     * @param  mixed  $value
     * @param  bool  $query
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    public static function url(mixed $value, bool $query = true): ?ViolationCode
    {
        $code = self::text($value, self::MAX_URL_LENGTH, false);

        if ($code !== null || !is_string($value)) {
            return $code;
        }

        $parts  = self::parts($value);
        $excess = isset($parts['user']) || isset($parts['pass']) || str_contains($value, '#') || (!$query && str_contains($value, '?'));

        return match (true) {
            $parts === null                          => ViolationCode::INVALID_FORMAT,
            strtolower($parts['scheme']) !== 'https' => ViolationCode::NOT_HTTPS,
            $excess                                  => ViolationCode::INVALID_FORMAT,
            default                                  => null,
        };
    }

    /**
     * `true` or `false`, and nothing that merely reads as one.
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    public static function boolean(mixed $value): ?ViolationCode
    {
        return is_bool($value) ? null : ViolationCode::INVALID_TYPE;
    }

    /**
     * One of the allowed strings, compared exactly.
     *
     * @param  mixed  $value
     * @param  array<array-key, mixed>  $allowed
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    public static function choice(mixed $value, array $allowed): ?ViolationCode
    {
        if (!is_string($value)) {
            return ViolationCode::INVALID_TYPE;
        }

        return in_array($value, $allowed, true) ? null : ViolationCode::NOT_ALLOWED;
    }

    /**
     * A list, as `array_is_list()` judges one.
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    public static function list(mixed $value): ?ViolationCode
    {
        return is_array($value) && array_is_list($value) ? null : ViolationCode::INVALID_TYPE;
    }

    /**
     * The problems with a list whose entries each come from an allow-list.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  array<array-key, mixed>  $allowed
     * @param  bool  $required
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    public static function allowedList(string $path, mixed $value, array $allowed, bool $required = true): array
    {
        $type = self::list($value);

        if ($type !== null || !is_array($value)) {
            return self::at($path, $type ?? ViolationCode::INVALID_TYPE);
        }

        if ($value === []) {
            return $required ? self::at($path, ViolationCode::REQUIRED) : [];
        }

        $violations = [];
        $seen       = [];

        foreach ($value as $index => $entry) {

            $code = self::choice($entry, $allowed) ?? (in_array($entry, $seen, true) ? ViolationCode::DUPLICATE : null);

            if ($code === null) {
                $seen[] = $entry;
            }

            array_push($violations, ...self::at($path . '.' . $index, $code));
        }

        return $violations;
    }

    /**
     * The violation at the path for the code, or none for no code.
     *
     * @param  string  $path
     * @param  ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode  $code
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    public static function at(string $path, ?ViolationCode $code): array
    {
        return $code === null ? [] : [new SettingViolation($path, $code)];
    }

    /**
     * The dotted path of the key, or the parent (`settings` at the top) when
     * the key is empty, unprintable or makes the path too long.
     *
     * @param  ?string  $parent
     * @param  int|string  $key
     * @return string
     */
    public static function path(?string $parent, int|string $key): string
    {
        $key  = (string) $key;
        $path = $parent === null ? $key : $parent . '.' . $key;

        if ($key === '' || !self::isPrintable($key) || strlen($path) > SettingViolation::MAX_SETTING_LENGTH) {
            return $parent ?? 'settings';
        }

        return $path;
    }

    /**
     * Compare maps regardless of key order, since a native JSON column may
     * reorder keys; lists are compared in order.
     *
     * @param  mixed  $one
     * @param  mixed  $other
     * @return bool
     */
    public static function isSame(mixed $one, mixed $other): bool
    {
        return self::canonical($one) === self::canonical($other);
    }

    /**
     * Whether the string is valid UTF-8 with no control character.
     *
     * @param  string  $value
     * @return bool
     */
    public static function isPrintable(#[\SensitiveParameter] string $value): bool
    {
        return mb_check_encoding($value, 'UTF-8') && preg_match(self::CONTROL, $value) !== 1;
    }

    /**
     * The parts of a URL with a scheme and a valid host, or `null`.
     *
     * @param  string  $value
     * @return ?array{scheme: string, host: string, port?: int<0, 65535>, user?: string, pass?: string, path?: string, query?: string, fragment?: string}
     */
    private static function parts(string $value): ?array
    {
        $parts = preg_match(self::AUTHORITY, $value) === 1 ? parse_url($value) : false;

        if (!is_array($parts) || !isset($parts['scheme'], $parts['host']) || preg_match(self::HOST, $parts['host']) !== 1) {
            return null;
        }

        return $parts;
    }

    /**
     * The value with every map in it ordered by key.
     *
     * @param  mixed  $value
     * @return mixed
     */
    private static function canonical(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        $value = array_map(self::canonical(...), $value);

        if (!array_is_list($value)) {
            ksort($value, SORT_STRING);
        }

        return $value;
    }
}
