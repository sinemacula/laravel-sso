<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Domains\DomainName;
use SineMacula\Laravel\Sso\Domains\DomainSettings;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\ReservationTerms;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Judges the conditions of linking by a verified domain (SSO-8.8), the one
 * place they are written, at completion and again at redemption:
 *
 * - the `domain_linking` feature is on, the connection's linking is on, its
 *   issuer is classified, an issuer of one organisation with the
 *   administrator's acknowledgement, and a shared issuer (one the administrator
 *   classified so, or one `requiredClaim()` knows, which is never downgraded)
 *   names its organisation claim and the expected value, which the result's
 *   accepted
 *   value equals exactly;
 * - the linking email came from the protocol: for SAML through the named
 *   attribute with the administrator's acknowledgement, for OIDC through the ID
 *   token or UserInfo, and never from attribute mapping;
 * - the linking policy version the response was validated under is the locked
 *   connection's;
 * - the email's domain, canonicalised (`Domains\DomainName::normalize()`, with
 *   the whitespace that trims refused, since an address is compared as
 *   asserted), is this connection's locked claim, whose standing allows linking
 *   (`Domains\DomainStanding::allowsLinking()`, not the result's mapped-email
 *   flag, since discovery's grace period authorises nothing here);
 * - `Contracts\LinkEmailMatcher` finds exactly one identity,
 *   `Contracts\PrincipalScope` answers `within_tenant` for it, and
 *   `Contracts\TenantMembership` answers a membership the person accepted
 *   strictly before the domain's current verification;
 * - the identity holds no link in the connection, and the subject none.
 *
 * It runs only under the package's link store: an alternative linker cannot
 * hold a reservation, so the combination reserves nothing and activates
 * nothing. `atCompletion()` answers the identity and the terms to reserve, with
 * the connection and result they stand on, or `null`. `isStillEligible()` answers whether everything still holds for that
 * same identity at redemption; another match never becomes the target.
 * `requiredClaim()` answers the organisation claim a known shared issuer must
 * be told apart by: one a preset with an organisation claim names
 * (`Protocols\Preset::names()`), or else one `LinkingSettings` lists.
 *
 * It holds the container, the clock, the settings and the presets, none of
 * which keeps anything of one flow for the next (SSO-11.2). A contract's
 * exception propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-type Eligible array{
 *     identity: \SineMacula\Laravel\Sso\Identities\IdentityReference,
 *     terms: \SineMacula\Laravel\Sso\Links\ReservationTerms,
 *     connection: \SineMacula\Laravel\Sso\Models\Connection,
 *     result: \SineMacula\Laravel\Sso\Results\VerifiedResult,
 * }
 */
final readonly class DomainLinkEligibility
{
    /** @var string The classification of an issuer many organisations share. */
    public const string SHARED = 'shared';

    /** @var string The classification of an issuer one organisation controls. */
    public const string SINGLE_ORGANIZATION = 'single_organization';

    /** @var string What a state with no consumed request means here. */
    private const string NOT_CONSUMED = 'A link is reserved once the request is consumed.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Linking\LinkingSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Domains\DomainSettings  $domains
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     */
    public function __construct(

        /** Resolves the application's contracts at each judgement. */
        private Container $container,

        /** The clock the domain's standing is judged at. */
        private Clock $clock,

        /** The known shared issuers. */
        private LinkingSettings $settings,

        /** The linking maximum age. */
        private DomainSettings $domains,

        /** The presets, some of which name shared issuers. */
        private ProtocolManager $protocols,
    ) {}

    /**
     * The identity to reserve for and the terms to reserve on, or `null` when
     * the state is not eligible.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?Eligible
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function atCompletion(CompletionState $state): ?array
    {
        $result = $state->result;
        $email  = $result?->linkingEmail;

        if ($result === null || $email === null || !self::isCandidate($state, $result)) {
            return null;
        }

        return $this->eligible($state, $result, $email);
    }

    /**
     * Whether everything a reservation of the identity stands on still holds at
     * redemption, for the result, under the locks, with the reservation itself
     * left out of what the identity holds.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function isStillEligible(VerifiedResult $result, IdentityReference $identity, Connection $connection, ?Domain $domain): bool
    {
        $email = $result->linkingEmail;

        if ($domain === null || $email === null || !$this->isStoreBound()) {
            return false;
        }

        if (!$this->allowsPolicy($connection, $result, $email) || !$this->allowsDomain($connection, $domain, $email)) {
            return false;
        }

        return $this->match($result, $email)->isSolely($identity)
            && $this->allowsIdentity($identity, $result->tenantId, $domain)
            && LinkStore::heldBy($connection->id, $identity, $this->clock->now()) === 1;
    }

    /**
     * The organisation claim the issuer must be told apart by, or `null` for an
     * issuer the package does not know to be shared. What the protocol's
     * presets name comes first, so configuration only ever adds an issuer, and
     * what `LinkingSettings` lists after it.
     *
     * @param  string  $protocol
     * @param  string  $issuer
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function requiredClaim(string $protocol, string $issuer): ?string
    {
        foreach ($this->protocols->presets() as $preset) {

            if ($preset->isSharedIssuer() && $preset->protocol === $protocol && $preset->names($issuer)) {
                return $preset->organizationClaim;
            }
        }

        return $this->settings->sharedIssuers()[$issuer] ?? null;
    }

    /**
     * Whether the result is of a `sign_in` whose link the state found absent.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return bool
     */
    private static function isCandidate(CompletionState $state, VerifiedResult $result): bool
    {
        return $result->purpose === Purpose::SIGN_IN && ($state->resolution?->isAbsent() ?? false);
    }

    /**
     * The identity and terms of the state, or `null` when a condition fails.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return ?Eligible
     *
     * @throws \LogicException
     */
    private function eligible(CompletionState $state, VerifiedResult $result, LinkingEmail $email): ?array
    {
        $connection = $state->connection ?? throw new \LogicException('A link is reserved once the connection is locked.');
        $domain     = $state->linkingDomain;

        if ($domain === null || !$this->allowsState($state, $connection, $domain, $result, $email)) {
            return null;
        }

        $identity = $this->match($result, $email)->identity;

        if ($identity === null || !$this->allowsIdentity($identity, $result->tenantId, $domain) || LinkStore::heldBy($connection->id, $identity, $this->clock->now()) !== 0) {
            return null;
        }

        $terms = $this->terms($state, $email, $domain, $connection);

        return $terms === null ? null : ['identity' => $identity, 'terms' => $terms, 'connection' => $connection, 'result' => $result];
    }

    /**
     * Whether the state's store, linking policy version, policy and domain
     * allow a reservation.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function allowsState(CompletionState $state, Connection $connection, Domain $domain, VerifiedResult $result, LinkingEmail $email): bool
    {
        if (!$this->isStoreBound() || $state->linkingVersion !== $connection->linking_version) {
            return false;
        }

        return $this->allowsPolicy($connection, $result, $email) && $this->allowsDomain($connection, $domain, $email);
    }

    /**
     * The terms of the reservation, or `null` when the request or application
     * leaves no time to redeem it.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Links\ReservationTerms
     *
     * @throws \LogicException
     */
    private function terms(CompletionState $state, LinkingEmail $email, Domain $domain, Connection $connection): ?ReservationTerms
    {
        $request     = $state->authorizationRequest ?? throw new \LogicException(self::NOT_CONSUMED);
        $application = $state->application          ?? throw new \LogicException(self::NOT_CONSUMED);
        $consumed    = $state->consumed             ?? throw new \LogicException(self::NOT_CONSUMED);
        $expiresAt   = $this->reservationExpiry($request, $application);

        return $expiresAt <= $this->clock->now()
            ? null
            : new ReservationTerms($consumed->reference, $email->email, $email->organization, $domain, $connection->linking_version, $expiresAt);
    }

    /**
     * When a reservation and its handoff expire: the earlier of the request's
     * expiry and the application's handoff lifetime from now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @return \Carbon\CarbonImmutable
     */
    private function reservationExpiry(AuthorizationRequest $request, Application $application): CarbonImmutable
    {
        return $this->clock->now()->addSeconds($application->handoffTtlSeconds)->min($request->expires_at);
    }

    /**
     * Whether the bound linker is the package's own store, the only one whose
     * rows a reservation can be.
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isStoreBound(): bool
    {
        return $this->container->make(Linker::class) instanceof LinkStore;
    }

    /**
     * Whether the connection's linking policy allows the result's email: the
     * feature and linking on, the issuer classified, the source the protocol's
     * own, and a shared issuer's organisation exactly its expected value.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function allowsPolicy(Connection $connection, VerifiedResult $result, LinkingEmail $email): bool
    {
        if (!Features::enabled(Feature::DOMAIN_LINKING) || !$connection->linking_enabled || !self::allowsSource($connection, $email)) {
            return false;
        }

        $required = $this->requiredClaim($connection->protocol, $result->issuer);

        if ($required !== null) {
            return self::allowsOrganization($connection, $email) && $connection->linking_organization_claim === $required;
        }

        return $connection->linking_issuer_class === self::SHARED ? self::allowsOrganization($connection, $email) : self::isAcknowledgedSingle($connection);
    }

    /**
     * Whether the connection is classified as one organisation's, with the
     * administrator's acknowledgement of that.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    private static function isAcknowledgedSingle(Connection $connection): bool
    {
        return $connection->linking_issuer_class === self::SINGLE_ORGANIZATION && $connection->linking_acknowledged_at !== null;
    }

    /**
     * Whether the connection is classified shared and the result's accepted
     * organisation is exactly its expected value, both set.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return bool
     */
    private static function allowsOrganization(Connection $connection, LinkingEmail $email): bool
    {
        $expected = $connection->linking_organization_value;

        return $connection->linking_issuer_class === self::SHARED
            && $connection->linking_organization_claim !== null
            && $expected                               !== null
            && $email->organization === $expected;
    }

    /**
     * Whether the email's source is the protocol's own, with a SAML
     * connection's acknowledgement that the provider decides who holds each
     * address.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return bool
     */
    private static function allowsSource(Connection $connection, LinkingEmail $email): bool
    {
        if ($email->source !== LinkingEmailSource::SAML_ATTRIBUTE) {
            return true;
        }

        return $connection->linking_acknowledged_at !== null && $connection->linking_saml_attribute !== null && $connection->linking_saml_attribute_format !== null;
    }

    /**
     * Whether the locked claim is this connection's claim of exactly the
     * email's canonicalised domain, and allows linking now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function allowsDomain(Connection $connection, Domain $domain, LinkingEmail $email): bool
    {
        if ($domain->connection_id !== $connection->id || $domain->domain !== self::canonicalDomain($email)) {
            return false;
        }

        return DomainStanding::allowsLinking($domain, $this->clock->now(), $this->domains->linkingMaxAgeSeconds());
    }

    /**
     * The email's domain as SSO-3.1 compares one, or `null` when it could be no
     * registered domain. The whitespace `DomainName::normalize()` would trim
     * from what an administrator typed is no part of an address, so it refuses
     * here.
     *
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return ?string
     */
    private static function canonicalDomain(LinkingEmail $email): ?string
    {
        $domain = $email->domain();

        return $domain === trim($domain) ? DomainName::normalize($domain) : null;
    }

    /**
     * What the link email contract finds for the result's email.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function match(VerifiedResult $result, LinkingEmail $email): LinkEmailMatch
    {
        $domain = self::canonicalDomain($email);

        if ($domain === null) {
            return LinkEmailMatch::none();
        }

        return $this->container->make(LinkEmailMatcher::class)->match(new LinkEmailQuery($result->tenantId, $email->email, $domain));
    }

    /**
     * Whether the identity's complete set of principals is within the tenant,
     * and the person accepted its membership before the domain's current
     * verification.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function allowsIdentity(IdentityReference $identity, string $tenantId, Domain $domain): bool
    {
        $verifiedAt = $domain->verified_at;

        if ($verifiedAt === null || !$this->container->make(PrincipalScope::class)->judge($identity, $tenantId)->isWithinTenant()) {
            return false;
        }

        return $this->container->make(TenantMembership::class)->standing($identity, $tenantId)->wasAcceptedBefore($verifiedAt);
    }
}
