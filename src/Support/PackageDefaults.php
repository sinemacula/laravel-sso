<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Support;

use SineMacula\Laravel\Sso\Applications\ConfiguredApplicationPolicy;
use SineMacula\Laravel\Sso\Applications\ConfiguredRedirectUriResolver;
use SineMacula\Laravel\Sso\Clock\SystemClock;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\HostResolver;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Domains\SystemDnsResolver;
use SineMacula\Laravel\Sso\Endpoints\ConfiguredEndpointResolver;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\NoExemptions;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use SineMacula\Laravel\Sso\Fetching\SystemHostResolver;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Linking\NoEmailMatches;
use SineMacula\Laravel\Sso\Linking\NoTenantMembership;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Linking\RefusingPrincipalScope;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Links\OneLinkPerConnection;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\Results\ProviderDeadlineLimitsSession;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;

/**
 * The defaults behind the package's seams and the package's own scoped state,
 * listed once for the provider that binds them and for `RequestState`, which
 * forgets the scoped ones.
 *
 * Each default is bound under its private key (`key()`), and the contract
 * forwards to that key, so a binding an application makes over the contract is
 * wholly its own. A default that holds nothing between calls is a singleton;
 * one that reads configuration or a connection is scoped (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PackageDefaults
{
    /** @var array<class-string, class-string> The singleton defaults, by contract. */
    public const array SINGLETONS = [
        Clock::class                    => SystemClock::class,
        HostResolver::class             => SystemHostResolver::class,
        Freshness::class                => RefusingFreshness::class,
        EnforcementInheritance::class   => OwnTenantInheritance::class,
        EnforcementExemption::class     => NoExemptions::class,
        SessionRevocation::class        => NoSessionRevocation::class,
        ApplicationPolicy::class        => ConfiguredApplicationPolicy::class,
        RedirectUriResolver::class      => ConfiguredRedirectUriResolver::class,
        Linker::class                   => NoLinks::class,
        LinkLimit::class                => OneLinkPerConnection::class,
        ReauthenticationSessions::class => NoReauthenticationSessions::class,
        LinkEligibility::class          => RefusingLinkEligibility::class,
        LinkConfirmation::class         => RefusingLinkConfirmation::class,
        LinkEmailMatcher::class         => NoEmailMatches::class,
        PrincipalScope::class           => RefusingPrincipalScope::class,
        TenantMembership::class         => NoTenantMembership::class,
        EvidencePolicy::class           => InsufficientEvidence::class,
        ProviderSessionDeadline::class  => ProviderDeadlineLimitsSession::class,
    ];

    /** @var array<class-string, class-string> The scoped defaults, by contract. */
    public const array SCOPED = [
        SingleUseStore::class   => DatabaseSingleUseStore::class,
        SecretEncrypter::class  => LaravelSecretEncrypter::class,
        Fetcher::class          => GuzzleFetcher::class,
        AttemptLimiter::class   => DatabaseAttemptLimiter::class,
        DnsResolver::class      => SystemDnsResolver::class,
        Enforcement::class      => DatabaseEnforcement::class,
        EndpointResolver::class => ConfiguredEndpointResolver::class,
        HandoffIssuer::class    => DatabaseHandoffStore::class,
    ];

    /** @var list<class-string> The package's own scoped classes, bound under their own names and never a seam. */
    public const array SCOPED_STATE = [
        DriverScope::class,
    ];

    /** @var string Prefix of the private key each default is bound under. */
    private const string KEY_PREFIX = 'sso.default:';

    /**
     * Return the private key the contract's default is bound under.
     *
     * @param  string  $contract
     * @return string
     */
    public static function key(string $contract): string
    {
        return self::KEY_PREFIX . $contract;
    }

    /**
     * Return every abstract the package binds as scoped: each scoped default's
     * private key, then its own scoped classes.
     *
     * @return list<string>
     */
    public static function scoped(): array
    {
        return [...array_map(self::key(...), array_keys(self::SCOPED)), ...self::SCOPED_STATE];
    }
}
