<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Linking;

use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;

/**
 * A tenant membership contract answering what the test sets, or throwing it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedTenantMembership implements TenantMembership
{
    /** @var ?\Throwable What it throws instead of answering. */
    public ?\Throwable $failure = null;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\MembershipStanding  $standing
     */
    public function __construct(

        /** What it answers. */
        public MembershipStanding $standing,
    ) {}

    /**
     * Answer the standing set.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\MembershipStanding
     *
     * @throws \Throwable
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $tenantId): MembershipStanding
    {
        unset($identity, $tenantId);

        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->standing;
    }
}
