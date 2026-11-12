<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ProviderContext;

/**
 * A stand-in for `laravel-authentication`'s `Proofs\Provenance`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Provenance
{
    /** @var ?\Carbon\CarbonImmutable When the provider authenticated the identity, to the second. */
    public ?CarbonImmutable $providerAuthenticatedAt;

    /** @var ?\Carbon\CarbonImmutable The provider's deadline for its session, to the second. */
    public ?CarbonImmutable $sessionNotAfter;

    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  ?string  $tenantId
     * @param  ?\Carbon\CarbonInterface  $providerAuthenticatedAt
     * @param  ?\Carbon\CarbonInterface  $sessionNotAfter
     * @param  ?string  $policyVersion
     * @param  ?string  $linkId
     * @param  ?\SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  ?\SineMacula\Laravel\Authentication\External\ProviderContext  $providerContext
     */
    public function __construct(

        /** The connection the session was established through. */
        public string $connectionId,

        /** The connection's tenant, if any. */
        public ?string $tenantId = null,

        // When the provider authenticated the identity, if it said
        ?CarbonInterface $providerAuthenticatedAt = null,

        // The provider's deadline for its session, if it gave one
        ?CarbonInterface $sessionNotAfter = null,

        /** The version of the policy the sign-in was judged by, if any. */
        public ?string $policyVersion = null,

        /** The link the identity signed in through, if any. */
        public ?string $linkId = null,

        /** The evidence the provider gave, if any. */
        public ?ExternalEvidence $evidence = null,

        /** The provider context the adapter gave at sign-in, if any. */
        public ?ProviderContext $providerContext = null,
    ) {
        $this->providerAuthenticatedAt = $providerAuthenticatedAt === null ? null : CarbonImmutable::instance($providerAuthenticatedAt)->startOfSecond();
        $this->sessionNotAfter         = $sessionNotAfter         === null ? null : CarbonImmutable::instance($sessionNotAfter)->startOfSecond();
    }
}
