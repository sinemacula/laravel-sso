<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Http;

use Illuminate\Http\Request;

/**
 * The client an action is taken for: the IP address it came from and the user
 * agent it sent, as plain values (SSO-11.2, SSO-11.8). Every public action that
 * counts an attempt against the client or records an event takes one, and none
 * reads the request being served itself: the application builds the context
 * where it reads the request, with `fromRequest()`, or from values it trusts,
 * with the constructor.
 *
 * The IP address and the user agent come from the client and are made safe to
 * keep rather than trusted, by the constructor, so a context built by hand is
 * held to the same rules as one read from a request: an IP address is kept only
 * when it is a valid IPv4 or IPv6 address, and a user agent has NUL bytes
 * removed, invalid UTF-8 replaced, and is cut to 512 characters. PostgreSQL,
 * and MySQL in strict mode, reject invalid UTF-8 and an over-long value, and a
 * crafted header must not turn a request into a server error; PostgreSQL cannot
 * store a NUL byte in text, and through PDO a value is cut short at the first
 * one. A value that is missing, invalid, or empty after cleaning is `null`.
 *
 * Work with no client (a console command, a queued job, a scheduled task) takes
 * `new ClientContext(null, null)`, built where that work starts: it counts
 * against no IP address, and its events carry neither value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientContext
{
    /** @var int Longest user agent kept, in characters. */
    private const int USER_AGENT_MAX_LENGTH = 512;

    /** @var ?string Validated IP address the client came from. */
    public ?string $ip;

    /** @var ?string Cleaned user agent the client sent. */
    public ?string $userAgent;

    /**
     * Constructor.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     */
    public function __construct(?string $ip, ?string $userAgent)
    {
        $this->ip        = self::cleanIp($ip);
        $this->userAgent = self::cleanUserAgent($userAgent);
    }

    /**
     * Read the client context of a request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        return new self($request->ip(), $request->userAgent());
    }

    /**
     * Keep an IP address only when it is a valid IPv4 or IPv6 address.
     *
     * @param  ?string  $ip
     * @return ?string
     */
    private static function cleanIp(?string $ip): ?string
    {
        return $ip !== null && filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
    }

    /**
     * Clean a user agent: NUL bytes removed, invalid UTF-8 replaced, cut to
     * `USER_AGENT_MAX_LENGTH` characters, and `null` when nothing is left.
     *
     * @param  ?string  $userAgent
     * @return ?string
     */
    private static function cleanUserAgent(?string $userAgent): ?string
    {
        if ($userAgent === null) {
            return null;
        }

        $cleaned = mb_substr(mb_scrub(str_replace("\0", '', $userAgent), 'UTF-8'), 0, self::USER_AGENT_MAX_LENGTH, 'UTF-8');

        return $cleaned === '' ? null : $cleaned;
    }
}
