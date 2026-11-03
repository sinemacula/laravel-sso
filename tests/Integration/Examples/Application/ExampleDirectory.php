<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Application;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;

/**
 * The example application's directory of people, as linking by a verified
 * domain asks it (SSO-8.8): whose verified email an address is, exactly as the
 * provider asserted it; whether a person's principals all sit within a tenant;
 * and since when a person has been a member of a tenant.
 *
 * It keeps its people in memory, which is all a test needs. An application's
 * own contracts read its users, principals and memberships, each with the guard
 * `docs/guides/linking-by-domain.md` describes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExampleDirectory implements LinkEmailMatcher, PrincipalScope, TenantMembership
{
    /** @var array<string, \SineMacula\Laravel\Sso\Identities\IdentityReference> Each person, by their verified email. */
    private array $emails = [];

    /** @var array<string, \Carbon\CarbonImmutable> When each person accepted each membership, by the person and the tenant. */
    private array $memberships = [];

    /**
     * Add a person with their verified email, a member of the tenant since the
     * instant given.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $person
     * @param  string  $verifiedEmail
     * @param  string  $tenantId
     * @param  \Carbon\CarbonImmutable  $memberSince
     * @return void
     */
    public function add(IdentityReference $person, string $verifiedEmail, string $tenantId, CarbonImmutable $memberSince): void
    {
        $this->emails[$verifiedEmail]                     = $person;
        $this->memberships[self::key($person, $tenantId)] = $memberSince;
    }

    /**
     * The one person whose verified email is exactly the address, if any.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\LinkEmailQuery  $query
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     */
    #[\Override]
    public function match(LinkEmailQuery $query): LinkEmailMatch
    {
        $person = $this->emails[$query->email()] ?? null;

        return $person === null ? LinkEmailMatch::none() : LinkEmailMatch::exactlyOne($person);
    }

    /**
     * Whether the person's principals all sit within the tenant: here, whether
     * they are a member of it.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     */
    #[\Override]
    public function judge(IdentityReference $identity, string $tenantId): ScopeVerdict
    {
        return isset($this->memberships[self::key($identity, $tenantId)]) ? ScopeVerdict::WITHIN_TENANT : ScopeVerdict::OUTSIDE_TENANT;
    }

    /**
     * The person's membership of the tenant, and when they accepted it.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\MembershipStanding
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $tenantId): MembershipStanding
    {
        $since = $this->memberships[self::key($identity, $tenantId)] ?? null;

        return $since === null ? MembershipStanding::none() : MembershipStanding::accepted($since);
    }

    /**
     * The key of the person's membership of the tenant.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return string
     */
    private static function key(IdentityReference $identity, string $tenantId): string
    {
        return implode("\n", [$identity->type, $identity->id, $tenantId]);
    }
}
