<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The one projection that builds an event's context (SSO-10.4, SSO-9.6):
 * nothing else in the package constructs an `EventContext`.
 *
 * Its parameter list is the admission control. It takes the fields a context
 * holds, each a string or `null`, and nothing else: no array and no object, so
 * a verified result, a request, a payload or a set of mapped attributes can
 * never be passed to an event whole, and a field the context does not name
 * cannot reach one. The flow's public reference is the only flow identifier it
 * takes (SSO-9.8). A later part of the package adds typed convenience methods
 * here (from a verified result, from an authorisation request) that pick the
 * fields they may and pass them on to `make()`.
 *
 * It reads the time from the package's clock and the client from the request
 * being served, resolved from the container on each call and never held, so a
 * long-lived worker (Octane, a queue) never attributes one request's event to
 * another's client (SSO-11.2). Every value is cleaned before it is kept: the IP
 * address is kept only when it is a valid IPv4 or IPv6 address; the user agent
 * and every named field have their control characters (C0, DEL, C1) and Unicode
 * bidirectional controls removed and invalid UTF-8 replaced, and are cut to
 * `USER_AGENT_MAX_LENGTH` and `FIELD_MAX_LENGTH` characters, so no value can
 * smuggle a payload, forge a log line or reorder text in an audit view; a value
 * that is empty once cleaned is `null`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EventContexts
{
    /** @var int Longest user agent kept, in characters. */
    public const int USER_AGENT_MAX_LENGTH = 512;

    /** @var int Longest named field kept, in characters. */
    public const int FIELD_MAX_LENGTH = 255;

    /** @var string Characters removed from every value: C0 controls, DEL, C1 controls and the Unicode bidirectional embeddings, overrides and isolates. */
    private const string UNSAFE_CHARACTERS = '/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The clock the time of each event is read from. */
        private Clock $clock,

        /** The container the request being served is resolved from on each call. */
        private Container $container,
    ) {}

    /**
     * Build the context of an event: the time from the clock, the client from
     * the request being served (none when no request is bound), and the fields
     * given, each cleaned and capped.
     *
     * @param  ?string  $connectionId
     * @param  ?string  $connectionTenantId
     * @param  ?string  $protocol
     * @param  ?string  $application
     * @param  ?string  $purpose
     * @param  ?string  $requestReference
     * @param  ?string  $identityMorphClass
     * @param  ?string  $identityId
     * @param  ?string  $actingIdentityMorphClass
     * @param  ?string  $actingIdentityId
     * @param  ?string  $principalMorphClass
     * @param  ?string  $principalId
     * @param  ?string  $tenantId
     * @param  ?string  $sessionId
     * @param  ?string  $method
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     *
     * @SuppressWarnings("php:S107")
     */
    public function make(
        ?string $connectionId = null,
        ?string $connectionTenantId = null,
        ?string $protocol = null,
        ?string $application = null,
        ?string $purpose = null,
        ?string $requestReference = null,
        ?string $identityMorphClass = null,
        ?string $identityId = null,
        ?string $actingIdentityMorphClass = null,
        ?string $actingIdentityId = null,
        ?string $principalMorphClass = null,
        ?string $principalId = null,
        ?string $tenantId = null,
        ?string $sessionId = null,
        ?string $method = null,
    ): EventContext {
        $request = $this->request();

        return new EventContext(
            occurredAt: $this->clock->now(),
            ip: self::ip($request?->ip()),
            userAgent: self::clean($request?->userAgent(), self::USER_AGENT_MAX_LENGTH),
            connectionId: self::field($connectionId),
            connectionTenantId: self::field($connectionTenantId),
            protocol: self::field($protocol),
            application: self::field($application),
            purpose: self::field($purpose),
            requestReference: self::field($requestReference),
            identityMorphClass: self::field($identityMorphClass),
            identityId: self::field($identityId),
            actingIdentityMorphClass: self::field($actingIdentityMorphClass),
            actingIdentityId: self::field($actingIdentityId),
            principalMorphClass: self::field($principalMorphClass),
            principalId: self::field($principalId),
            tenantId: self::field($tenantId),
            sessionId: self::field($sessionId),
            method: self::field($method),
        );
    }

    /**
     * The request being served, resolved now, or `null` when none is bound.
     *
     * @return ?\Illuminate\Http\Request
     */
    private function request(): ?Request
    {
        if (!$this->container->bound('request')) {
            return null;
        }

        return $this->container->make('request');
    }

    /**
     * Keep an IP address only when it is a valid IPv4 or IPv6 address.
     *
     * @param  ?string  $ip
     * @return ?string
     */
    private static function ip(?string $ip): ?string
    {
        return $ip !== null && filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
    }

    /**
     * Clean a named field and cap it at `FIELD_MAX_LENGTH` characters.
     *
     * @param  ?string  $value
     * @return ?string
     */
    private static function field(?string $value): ?string
    {
        return self::clean($value, self::FIELD_MAX_LENGTH);
    }

    /**
     * Clean a value: invalid UTF-8 replaced, control and bidirectional
     * characters removed, cut to `$maxLength` characters, and `null` when
     * nothing is left.
     *
     * @param  ?string  $value
     * @param  int  $maxLength
     * @return ?string
     */
    private static function clean(?string $value, int $maxLength): ?string
    {
        if ($value === null) {
            return null;
        }

        $cleaned = mb_substr((string) preg_replace(self::UNSAFE_CHARACTERS, '', mb_scrub($value, 'UTF-8')), 0, $maxLength, 'UTF-8');

        return $cleaned === '' ? null : $cleaned;
    }
}
