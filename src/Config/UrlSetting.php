<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config;

/**
 * Reads a URL setting, failing closed with a message that never quotes the
 * configured value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UrlSetting
{
    /** @var int The longest URL accepted. */
    private const int MAX_LENGTH = 2048;

    /** @var list<string> The loopback hosts an `http` URL may name, as `parse_url()` gives them. */
    private const array LOOPBACK_HOSTS = ['127.0.0.1', '[::1]'];

    /** @var string A private-use scheme: lower case with a dot (RFC 8252 section 7.1). */
    private const string PRIVATE_USE_SCHEME = '/^[a-z][a-z0-9+\-]*(?:\.[a-z0-9+\-]+)+$/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The value as a web URL: `https`, or `http` on a loopback address.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  bool  $query
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function web(string $key, mixed $value, bool $query = true): string
    {
        $what = 'an absolute https URL (or http on 127.0.0.1 or [::1]) with no user information, fragment or wildcard' . ($query ? '' : ', or query');

        [$url, $parts] = self::parts($key, $value, $what);

        if (!self::isWeb($parts) || (!$query && isset($parts['query']))) {
            throw self::refused($key, $what);
        }

        return $url;
    }

    /**
     * The value as a redirect URI: a web URL or a native app's private-use
     * scheme.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function redirect(string $key, mixed $value): string
    {
        $what = 'an exact redirect URI: an absolute https URL (or http on 127.0.0.1 or [::1]), or a private-use scheme with a dot'
            . ' (`com.example.app:/callback`), with no user information, fragment or wildcard';

        [$url, $parts] = self::parts($key, $value, $what);

        if (!self::isWeb($parts) && !self::isPrivateUse($parts)) {
            throw self::refused($key, $what);
        }

        return $url;
    }

    /**
     * The parts of the URL, refusing whitespace, controls, wildcards, fragments
     * and user information.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $what
     * @return array{0: string, 1: array{scheme?: string, host?: string, port?: int, user?: string, pass?: string, path?: string, query?: string, fragment?: string}}
     *
     * @throws \InvalidArgumentException
     */
    private static function parts(string $key, mixed $value, string $what): array
    {
        if (!is_string($value) || $value === '' || strlen($value) > self::MAX_LENGTH || preg_match('/[\x00-\x20\x7f*#\\\]/', $value) === 1) {
            throw self::refused($key, $what);
        }

        $parts = parse_url($value);

        if ($parts === false || !isset($parts['scheme']) || isset($parts['user']) || isset($parts['pass'])) {
            throw self::refused($key, $what);
        }

        return [$value, $parts];
    }

    /**
     * Whether the parts are a web URL's.
     *
     * @param  array{scheme?: string, host?: string, port?: int, user?: string, pass?: string, path?: string, query?: string, fragment?: string}  $parts
     * @return bool
     */
    private static function isWeb(array $parts): bool
    {
        $host = $parts['host'] ?? '';

        return match ($parts['scheme'] ?? null) {
            'https' => $host !== '',
            'http'  => in_array($host, self::LOOPBACK_HOSTS, true),
            default => false,
        };
    }

    /**
     * Whether the parts are a private-use scheme's.
     *
     * @param  array{scheme?: string, host?: string, port?: int, user?: string, pass?: string, path?: string, query?: string, fragment?: string}  $parts
     * @return bool
     */
    private static function isPrivateUse(array $parts): bool
    {
        return preg_match(self::PRIVATE_USE_SCHEME, $parts['scheme'] ?? '') === 1;
    }

    /**
     * The exception for a value that is not what the key must be.
     *
     * @param  string  $key
     * @param  string  $what
     * @return \InvalidArgumentException
     */
    private static function refused(string $key, string $what): \InvalidArgumentException
    {
        return new \InvalidArgumentException(sprintf('`%s` must be %s.', $key, $what));
    }
}
