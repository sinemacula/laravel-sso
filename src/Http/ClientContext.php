<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Http;

use Illuminate\Http\Request;

/**
 * The client's IP address and user agent, cleaned so they are safe to store.
 *
 * PostgreSQL and strict MySQL reject invalid UTF-8, NUL bytes and over-long
 * values, and a crafted header must not become a server error.
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

    /** @var string Control and Unicode bidirectional characters removed from a user agent. */
    private const string UNSAFE_CHARACTERS = '/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{061C}\x{200E}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';

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
     * Clean a user agent, cutting it to length only after removals; `null` when
     * nothing is left.
     *
     * @param  ?string  $userAgent
     * @return ?string
     */
    private static function cleanUserAgent(?string $userAgent): ?string
    {
        if ($userAgent === null) {
            return null;
        }

        $cleaned = mb_substr((string) preg_replace(self::UNSAFE_CHARACTERS, '', mb_scrub($userAgent, 'UTF-8')), 0, self::USER_AGENT_MAX_LENGTH, 'UTF-8');

        return $cleaned === '' ? null : $cleaned;
    }
}
