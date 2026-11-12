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
 * Builds a completion's verified result, only ever from what a driver verified.
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
     * Build the verified result of the claims.
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
            assertedEmail: $claims->assertedEmail,
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
     * The email's normalised domain, or `null` without a local part and a valid
     * domain.
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
