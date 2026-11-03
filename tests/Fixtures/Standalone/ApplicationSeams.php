<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Standalone;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FrozenClock;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\ScriptedEmailMatcher;
use Tests\Fixtures\Linking\ScriptedLinkConfirmation;
use Tests\Fixtures\Linking\ScriptedPrincipalScope;
use Tests\Fixtures\Linking\ScriptedTenantMembership;

/**
 * Everything a complete application binds at once, the seams an adapter of its
 * own stands behind and the outside world it fakes in a test: the linker, the
 * issuer, its sessions and their revocation, its freshness, its single-use
 * store on a connection of its own, its attempt limiter, the clock, the fetcher
 * and the DNS resolver, and the application's answers about its people.
 * `seams()` lists them, so a test shows each is what the package was given.
 *
 * The seams left out are ones an application rarely replaces and that hold no
 * state of its own (the enforcement, inheritance and exemption contracts, the
 * application policy, the redirect URI and endpoint resolvers, and the link
 * limit): they stay on their defaults, as most applications leave them.
 *
 * Nothing here is shared between tests: a test builds one, which binds it all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationSeams
{
    /** @var \SineMacula\Laravel\Sso\Testing\FrozenClock The clock the package reads. */
    public readonly FrozenClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver What answers every DNS lookup. */
    public readonly FakeDnsResolver $dns;

    /** @var \Tests\Fixtures\Standalone\ApplicationFreshness How the application judges its caller. */
    public readonly ApplicationFreshness $freshness;

    /** @var \Tests\Fixtures\Standalone\ApplicationRevocation The application's sessions. */
    public readonly ApplicationRevocation $sessions;

    /** @var \Tests\Fixtures\Standalone\ApplicationSingleUseStore The application's single-use store. */
    public readonly ApplicationSingleUseStore $singleUse;

    /** @var \Tests\Fixtures\Standalone\ApplicationAttemptLimiter The application's attempt limiter. */
    public readonly ApplicationAttemptLimiter $limiter;

    /** @var \Tests\Fixtures\Linking\ScriptedEmailMatcher Whom an email belongs to. */
    public readonly ScriptedEmailMatcher $matcher;

    /** @var \Tests\Fixtures\Linking\ScriptedPrincipalScope What the application's principals allow. */
    public readonly ScriptedPrincipalScope $scope;

    /** @var \Tests\Fixtures\Linking\ScriptedTenantMembership Whose membership a tenant holds. */
    public readonly ScriptedTenantMembership $membership;

    /** @var \Tests\Fixtures\Linking\ScriptedLinkConfirmation Whether a caller stands apart from their domain links. */
    public readonly ScriptedLinkConfirmation $confirmation;

    /** @var \Tests\Fixtures\Linking\AllowingLinkEligibility Who may link. */
    public readonly AllowingLinkEligibility $eligibility;

    /** @var \SineMacula\Laravel\Sso\Contracts\EvidencePolicy What a provider's assertion counts for. */
    public readonly EvidencePolicy $evidence;

    /** @var \SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline Whether the provider's deadline limits a session. */
    public readonly ProviderSessionDeadline $deadline;

    /** @var \Tests\Fixtures\Standalone\ApplicationLinker The application's linker. */
    public readonly ApplicationLinker $linker;

    /** @var \Tests\Fixtures\Standalone\ApplicationHandoffIssuer The application's handoff issuer. */
    public readonly ApplicationHandoffIssuer $issuer;

    /**
     * Make every seam and bind it in the container, the clock first, since what
     * the package builds for the wrappers reads it.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $now
     * @param  \SineMacula\Laravel\Sso\Testing\FakeFetcher  $fetcher
     */
    public function __construct(

        // Where the application binds its seams
        Container $container,

        // The instant the clock holds
        string $now,

        /** What every provider answers on. */
        public readonly FakeFetcher $fetcher,
    ) {
        $this->clock        = new FrozenClock($now);
        $this->dns          = new FakeDnsResolver;
        $this->freshness    = new ApplicationFreshness($this->clock);
        $this->sessions     = new ApplicationRevocation;
        $this->singleUse    = new ApplicationSingleUseStore($this->clock);
        $this->limiter      = new ApplicationAttemptLimiter;
        $this->matcher      = new ScriptedEmailMatcher(LinkEmailMatch::none());
        $this->scope        = new ScriptedPrincipalScope;
        $this->membership   = new ScriptedTenantMembership(MembershipStanding::accepted(CarbonImmutable::parse($now)->subDays(2)));
        $this->confirmation = new ScriptedLinkConfirmation;
        $this->eligibility  = new AllowingLinkEligibility;
        $this->evidence     = self::evidencePolicy();
        $this->deadline     = self::ignoredDeadline();

        $container->instance(Clock::class, $this->clock);

        $this->linker = new ApplicationLinker($container->make(LinkStore::class));
        $this->issuer = new ApplicationHandoffIssuer($container->make(DatabaseHandoffStore::class));

        foreach ($this->seams() as $seam => $bound) {
            $container->instance($seam, $bound);
        }
    }

    /**
     * Each seam, and what the application binds it to.
     *
     * @return array<class-string, object>
     */
    public function seams(): array
    {
        return [
            Clock::class                    => $this->clock,
            Fetcher::class                  => $this->fetcher,
            DnsResolver::class              => $this->dns,
            Freshness::class                => $this->freshness,
            Linker::class                   => $this->linker,
            HandoffIssuer::class            => $this->issuer,
            SessionRevocation::class        => $this->sessions,
            ReauthenticationSessions::class => $this->sessions,
            SingleUseStore::class           => $this->singleUse,
            AttemptLimiter::class           => $this->limiter,
            LinkEmailMatcher::class         => $this->matcher,
            PrincipalScope::class           => $this->scope,
            TenantMembership::class         => $this->membership,
            LinkConfirmation::class         => $this->confirmation,
            LinkEligibility::class          => $this->eligibility,
            EvidencePolicy::class           => $this->evidence,
            ProviderSessionDeadline::class  => $this->deadline,
        ];
    }

    /**
     * An evidence policy that accepts what a result says of when the provider
     * authenticated.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\EvidencePolicy
     */
    private static function evidencePolicy(): EvidencePolicy
    {
        return new readonly class implements EvidencePolicy {
            /**
             * Accept the result's authentication, when it states one.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \Carbon\CarbonImmutable  $now
             * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
             */
            #[\Override]
            public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
            {
                unset($now);

                $authenticatedAt = $result->authenticationContext->authenticatedAt;

                return $authenticatedAt === null ? null : new AcceptedEvidence($connection->getConnectionId(), $authenticatedAt);
            }
        };
    }

    /**
     * A deadline contract for an application that keeps its sessions apart from
     * the provider's.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline
     */
    private static function ignoredDeadline(): ProviderSessionDeadline
    {
        return new readonly class implements ProviderSessionDeadline {
            /**
             * The deadline limits nothing.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect
             */
            #[\Override]
            public function effect(VerifiedResult $result): DeadlineEffect
            {
                unset($result);

                return DeadlineEffect::IGNORED;
            }
        };
    }
}
