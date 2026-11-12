<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Http\ClientContext;

/**
 * The only place an `EventContext` is built, cleaning and capping every value.
 *
 * It takes strings only, so a result, request or attribute set never reaches an
 * event whole.
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

    /** @var string C0, DEL, C1 and bidirectional embeddings, overrides and isolates. */
    private const string UNSAFE_CHARACTERS = '/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock the time of each event is read from. */
        private Clock $clock,
    ) {}

    /**
     * Build an event's context from the given client, never the request being
     * served, so a long-lived worker cannot misattribute it.
     *
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
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
        ClientContext $client,
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
        return new EventContext(
            occurredAt: $this->clock->now(),
            ip: self::ip($client->ip),
            userAgent: self::clean($client->userAgent, self::USER_AGENT_MAX_LENGTH),
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
     * Keep an IP address only when it is valid.
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
     * Scrub invalid UTF-8, strip unsafe characters and cap the length; `null`
     * when nothing is left.
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
