<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict;

/**
 * The example application's link eligibility (SSO-8.5): an identity may link
 * through a connection only as a member of the connection's tenant. It reads
 * the membership from the write connection, locked on the package's storage
 * connection, so a membership that exists stays until the redemption commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MembersMayLink implements LinkEligibility
{
    // @snippet-start links-eligibility
    /**
     * Whether the identity is a member of the connection's tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkEligibilityVerdict
     */
    #[\Override]
    public function judge(IdentityReference $identity, SsoConnection $connection): LinkEligibilityVerdict
    {
        // Read on the package's storage connection, so this lock holds until
        // the redemption commits
        $member = Membership::on(StorageConnection::name())
            ->useWritePdo()
            ->where('identity_type', $identity->type)
            ->where('identity_id', $identity->id)
            ->where('tenant_id', $connection->getTenantId())
            ->lockForUpdate()
            ->first();

        return $member !== null ? LinkEligibilityVerdict::ELIGIBLE : LinkEligibilityVerdict::INELIGIBLE;
    }
    // @snippet-end links-eligibility
}
