<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;

/**
 * Who and what a package event is about (SSO-9.6, SSO-10.4): the connection,
 * its tenant and protocol, the application and the purpose, the authorisation
 * request's public reference, the identity and the acting identity, the client
 * the request came from, and, where they apply, the principal, the active
 * tenant, the session and the sign-in method, under the names
 * `laravel-authentication`'s events give them (AUTH-9.4). Every package event
 * carries one, so a single listener on `Contracts\SsoEvent` can attribute them
 * all the same way.
 *
 * It holds strings only, fixed when it is built, so it survives a queue
 * unchanged and `toArray()` is the record an audit sink keeps. A part the
 * event's flow did not establish, or that does not apply to it, is `null`.
 * `tenantId` is the tenant of the connection the event concerns;
 * `activeTenantId` is the tenant a session is active in, where an event
 * concerns a session. The public reference is the only flow identifier it ever
 * holds (SSO-9.8).
 *
 * It is built only by the package's event projection, which admits these fields
 * and nothing else: never a secret, assertion, provider token, verifier,
 * handoff code, protocol state, raw payload, transport header or mapped
 * attribute (SSO-10.4). A verified result is never passed to an event whole.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, ?string>
 */
final readonly class EventContext implements Arrayable
{
    /**
     * Constructor.
     *
     * @param  \Carbon\CarbonImmutable  $occurredAt
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @param  ?string  $connectionId
     * @param  ?string  $tenantId
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
     * @param  ?string  $activeTenantId
     * @param  ?string  $sessionId
     * @param  ?string  $method
     */
    public function __construct(

        /** When the event was built, from the package's clock. */
        public CarbonImmutable $occurredAt,

        /** IP address of the client of the request being served. */
        public ?string $ip = null,

        /** User agent of the client of the request being served, length capped. */
        public ?string $userAgent = null,

        /** Id of the connection the event concerns. */
        public ?string $connectionId = null,

        /** Opaque id of the tenant the connection belongs to. */
        public ?string $tenantId = null,

        /** Protocol of the connection (`saml2`, `oidc` or a registered driver's). */
        public ?string $protocol = null,

        /** Name of the application the flow is for. */
        public ?string $application = null,

        /** Purpose of the flow (`sign_in`, `link` or `reauthenticate`). */
        public ?string $purpose = null,

        /** Public reference of the authorisation request, the only flow identifier an event carries. */
        public ?string $requestReference = null,

        /** Type of the identity reference (under `laravel-iam`, the identity's morph class). */
        public ?string $identityMorphClass = null,

        /** Id of the identity reference. */
        public ?string $identityId = null,

        /** Type of the identity acting, for administration, as the application passes it. */
        public ?string $actingIdentityMorphClass = null,

        /** Id of the identity acting, for administration, as the application passes it. */
        public ?string $actingIdentityId = null,

        /** Morph class of the principal, where a session's principal applies. */
        public ?string $principalMorphClass = null,

        /** Id of the principal, where a session's principal applies. */
        public ?string $principalId = null,

        /** Opaque id of the tenant a session is active in, where one applies. */
        public ?string $activeTenantId = null,

        /** Id of the session, where one applies. */
        public ?string $sessionId = null,

        /** Name of the sign-in method, where one applies. */
        public ?string $method = null,
    ) {}

    /**
     * Return the context as scalars, the record an audit sink keeps: snake_case
     * keys, and the time as an ISO 8601 UTC string to the microsecond.
     *
     * @return array<string, ?string>
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'occurred_at'                 => $this->occurredAt->utc()->format('Y-m-d\TH:i:s.u\Z'),
            'ip'                          => $this->ip,
            'user_agent'                  => $this->userAgent,
            'connection_id'               => $this->connectionId,
            'tenant_id'                   => $this->tenantId,
            'protocol'                    => $this->protocol,
            'application'                 => $this->application,
            'purpose'                     => $this->purpose,
            'request_reference'           => $this->requestReference,
            'identity_morph_class'        => $this->identityMorphClass,
            'identity_id'                 => $this->identityId,
            'acting_identity_morph_class' => $this->actingIdentityMorphClass,
            'acting_identity_id'          => $this->actingIdentityId,
            'principal_morph_class'       => $this->principalMorphClass,
            'principal_id'                => $this->principalId,
            'active_tenant_id'            => $this->activeTenantId,
            'session_id'                  => $this->sessionId,
            'method'                      => $this->method,
        ];
    }
}
