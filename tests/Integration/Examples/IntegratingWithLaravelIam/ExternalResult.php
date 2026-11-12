<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Carbon\CarbonImmutable;

/**
 * A stand-in for `laravel-authentication`'s `ExternalResult`, holding the
 * provider context as the values its `ProviderContext` would hold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalResult
{
    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @param  string  $tenantId
     * @param  ?\Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\Carbon\CarbonImmutable  $sessionNotAfter
     * @param  ?string  $policyVersion
     * @param  list<string>  $evidenceMethods
     * @param  ?string  $linkId
     * @param  ?string  $requestReference
     * @param  ?array<string, mixed>  $providerContext
     */
    public function __construct(

        /** The connection the person signed in through. */
        public string $connectionId,

        /** The provider's issuer. */
        public string $issuer,

        /** The person's subject at the provider. */
        public string $subject,

        /** The connection's tenant. */
        public string $tenantId,

        /** When the provider authenticated the person, if it said. */
        public ?CarbonImmutable $authenticatedAt,

        /** The session's effective latest end, if any. */
        public ?CarbonImmutable $sessionNotAfter,

        /** The enforcement version the redemption judged under its locks. */
        public ?string $policyVersion,

        /** The authentication methods the evidence contract accepted. */
        public array $evidenceMethods,

        /** The link the redemption resolved; the link contract must match it. */
        public ?string $linkId,

        /** The authorisation request's public reference, for correlating events. */
        public ?string $requestReference = null,

        /** The stored form of the package's provenance. */
        public ?array $providerContext = null,
    ) {}
}
