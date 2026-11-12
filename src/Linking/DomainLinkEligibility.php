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
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Domains\DomainName;
use SineMacula\Laravel\Sso\Domains\DomainSettings;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\ReservationTerms;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The one place the conditions of linking by a verified domain are judged, at
 * completion and again at redemption.
 *
 * What an identity holds is read by a locking read before any application
 * contract is asked.
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

    /** @var string What refuses a linker not backed by link storage names. */
    private const string OPERATION = 'Linking by a verified domain';

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
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
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

        /** Whether the bound linker is backed by link storage. */
        private LinkStorageBinding $storage,
    ) {}

    /**
     * The email's normalised domain, or `null`; surrounding whitespace is
     * refused, since an address is compared as asserted.
     *
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return ?string
     */
    public static function canonicalDomain(LinkingEmail $email): ?string
    {
        $domain = $email->domain();

        return $domain === trim($domain) ? DomainName::normalize($domain) : null;
    }

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
     * Whether the reservation's conditions still hold for that same identity at
     * redemption, under the locks.
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

        if ($domain === null || $email === null) {
            return false;
        }

        $held = $this->storage->require(self::OPERATION)->holdings($connection->id, $identity);

        if ($held !== 1 || !$this->allowsPolicy($connection, $result, $email) || !$this->allowsDomain($connection, $domain, $email)) {
            return false;
        }

        return $this->match($result, $email)->isSolely($identity) && $this->allowsIdentity($identity, $result->tenantId, $domain);
    }

    /**
     * A known shared issuer's organisation claim, or `null`; presets come
     * first, so configuration only adds.
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
     * What the link email contract finds for the result's email.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function match(VerifiedResult $result, LinkingEmail $email): LinkEmailMatch
    {
        $domain = self::canonicalDomain($email);

        if ($domain === null) {
            return LinkEmailMatch::none();
        }

        return $this->container->make(LinkEmailMatcher::class)->match(new LinkEmailQuery($result->tenantId, $email->email, $domain));
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

        $guarded  = $state->linkingDiscovery?->identity;
        $held     = $guarded === null ? 0 : $this->storage->require(self::OPERATION)->holdings($connection->id, $guarded);
        $identity = $this->match($result, $email)->identity;

        if ($identity === null || !$this->allowsMatched($identity, $guarded, $held, $result, $domain)) {
            return null;
        }

        $terms = $this->terms($state, $email, $domain, $connection);

        return $terms === null ? null : ['identity' => $identity, 'terms' => $terms, 'connection' => $connection, 'result' => $result];
    }

    /**
     * Whether the match goes on; one whose guard is not held passes unasked,
     * for the stage to refuse.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $guarded
     * @param  int  $held
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function allowsMatched(IdentityReference $identity, ?IdentityReference $guarded, int $held, VerifiedResult $result, Domain $domain): bool
    {
        if ($guarded === null || !$guarded->is($identity)) {
            return true;
        }

        return $held === 0 && $this->allowsIdentity($identity, $result->tenantId, $domain);
    }

    /**
     * Whether the store, policy version, policy and domain allow a reservation.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function allowsState(CompletionState $state, Connection $connection, Domain $domain, VerifiedResult $result, LinkingEmail $email): bool
    {
        $this->storage->require(self::OPERATION);

        if ($state->linkingVersion !== $connection->linking_version) {
            return false;
        }

        return $this->allowsPolicy($connection, $result, $email) && $this->allowsDomain($connection, $domain, $email);
    }

    /**
     * The reservation's terms, or `null` when no time is left to redeem it.
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
     * The earlier of the request's expiry and the application's handoff
     * lifetime from now.
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
     * Whether the connection's linking policy allows the result's email.
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
     * Whether the connection is classified single-organisation and
     * acknowledged.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    private static function isAcknowledgedSingle(Connection $connection): bool
    {
        return $connection->linking_issuer_class === self::SINGLE_ORGANIZATION && $connection->linking_acknowledged_at !== null;
    }

    /**
     * Whether the connection is shared and the organisation is exactly its
     * expected value.
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
     * Whether the email came from the protocol itself, a SAML attribute only
     * with acknowledgement.
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
     * Whether the locked claim is this connection's for the email's domain and
     * allows linking now.
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
     * Whether the identity is within the tenant and accepted its membership
     * before the domain's verification.
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
