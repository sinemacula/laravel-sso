<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use SineMacula\Laravel\Sso\Connections\AttributeMapping;
use SineMacula\Laravel\Sso\Connections\MappingLimits;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Domains\DomainFinder;
use SineMacula\Laravel\Sso\Domains\DomainName;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Builds the verified result of a completion (SSO-8.1), the only place one is
 * made from what a driver verified: never from client input.
 *
 * - The issuer, subject, NameID format, authentication context and linking
 *   email are the claims', exactly as the driver verified them (SSO-6.9).
 * - The connection, its tenant and its protocol are the connection's the
 *   response arrived for, read from the write connection.
 * - The application, purpose and public reference are the consumed request's.
 * - The attributes are the claims' raw attributes read through the connection's
 *   attribute mapping (SSO-2.10), capped by `sso.mapping`.
 * - The email's domain is verified exactly when the mapped `email` is a string
 *   with a local part, an `@` and a domain that normalises
 *   (`Domains\DomainName`), and that domain routes for this same connection at
 *   the clock's now (`Domains\DomainStanding::routes()`, SSO-3.3): verified and
 *   not past its grace period. A domain of another connection, pending or
 *   lapsed, or an email that is not one, is not verified. The domain is read
 *   from the write connection (SSO-11.3).
 *
 * It holds the mapping caps, the domain finder and the clock, none of which
 * keeps anything of one completion for the next (SSO-11.2). A database error
 * propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResultBuilder
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\MappingLimits  $limits
     * @param  \SineMacula\Laravel\Sso\Domains\DomainFinder  $domains
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The caps on what the mapping carries. */
        private MappingLimits $limits,

        /** Finds the connection's claim of the email's domain. */
        private DomainFinder $domains,

        /** The clock the domain's standing is judged at. */
        private Clock $clock,
    ) {}

    /**
     * The verified result of the claims, for the connection and the consumed
     * request.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \InvalidArgumentException
     */
    public function build(VerifiedClaims $claims, Connection $connection, ConsumedRequest $consumed): VerifiedResult
    {
        $attributes = AttributeMapping::fromArray($connection->protocol, $connection->attribute_mapping, $this->limits)->map($claims->attributes);

        return new VerifiedResult(
            issuer: $claims->issuer,
            subject: $claims->subject,
            nameIdFormat: $claims->nameIdFormat,
            connectionId: $connection->id,
            tenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            application: $consumed->application,
            purpose: $consumed->purpose,
            requestReference: $consumed->reference,
            attributes: $attributes,
            emailDomainVerified: $this->isVerifiedEmail($attributes['email'] ?? null, $connection),
            authenticationContext: $claims->authenticationContext,
            linkingEmail: $claims->linkingEmail,
        );
    }

    /**
     * Whether the mapped email is a string whose domain routes for the
     * connection now.
     *
     * @param  list<string>|string|null  $email
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    private function isVerifiedEmail(array|string|null $email, Connection $connection): bool
    {
        $domain = is_string($email) ? self::domainOf($email) : null;
        $claim  = $domain === null ? null : $this->domains->find($connection, $domain);

        return $claim !== null && DomainStanding::routes($claim, $this->clock->now());
    }

    /**
     * The email's domain, normalised, or `null` when the email has no local
     * part, no `@`, or a domain that does not normalise.
     *
     * @param  string  $email
     * @return ?string
     */
    private static function domainOf(string $email): ?string
    {
        $at = strrpos($email, '@');

        return $at === false || $at === 0 ? null : DomainName::normalize(substr($email, $at + 1));
    }
}
