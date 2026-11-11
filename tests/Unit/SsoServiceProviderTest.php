<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Applications\ConfiguredApplicationPolicy;
use SineMacula\Laravel\Sso\Applications\ConfiguredRedirectUriResolver;
use SineMacula\Laravel\Sso\Clock\SystemClock;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
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
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\SystemDnsResolver;
use SineMacula\Laravel\Sso\Endpoints\ConfiguredEndpointResolver;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\NoExemptions;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Events\StrandedTransactions;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use SineMacula\Laravel\Sso\Fetching\SystemHostResolver;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Keys\ExpiryNotifier;
use SineMacula\Laravel\Sso\Linking\NoEmailMatches;
use SineMacula\Laravel\Sso\Linking\NoTenantMembership;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use SineMacula\Laravel\Sso\Linking\RefusingLinkEligibility;
use SineMacula\Laravel\Sso\Linking\RefusingPrincipalScope;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Links\OneLinkPerConnection;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\OidcMetadataSource;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Metadata\SamlMetadataSource;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCompletion;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClaimsAssembler;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\UnsolicitedResponses;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Pruning\Pruner;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\Results\ProviderDeadlineLimitsSession;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Fixtures\Fetching\StubHostResolver;

/**
 * Unit tests for the package SsoServiceProvider, on a bare application with no
 * framework bootstrapping: what registering merges and binds, how each default
 * is shared, that a binding made before is kept and one made after outlives
 * every scope, and which seams are still the package's defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
final class SsoServiceProviderTest extends TestCase
{
    /** @var list<class-string> Every seam the provider binds a default for, each only while nothing is bound to it yet. */
    private const array SEAMS = [
        ApplicationPolicy::class, AttemptLimiter::class, Clock::class, DnsResolver::class, EndpointResolver::class,
        Enforcement::class, EnforcementExemption::class, EnforcementInheritance::class, EvidencePolicy::class,
        Fetcher::class, Freshness::class, HandoffIssuer::class, HostResolver::class, LinkConfirmation::class,
        LinkEligibility::class, LinkEmailMatcher::class, LinkLimit::class, Linker::class, PrincipalScope::class,
        ProviderSessionDeadline::class, ReauthenticationSessions::class, RedirectUriResolver::class,
        SecretEncrypter::class, SessionRevocation::class, SingleUseStore::class, TenantMembership::class,
    ];

    /** @var array<class-string, class-string> Each seam whose default holds nothing between calls, with its default. */
    private const array SINGLETON_DEFAULTS = [
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

    /** @var array<class-string, class-string> Each seam whose default reads configuration or a connection, with its default. */
    private const array SCOPED_DEFAULTS = [
        SingleUseStore::class   => DatabaseSingleUseStore::class,
        SecretEncrypter::class  => LaravelSecretEncrypter::class,
        Fetcher::class          => GuzzleFetcher::class,
        AttemptLimiter::class   => DatabaseAttemptLimiter::class,
        DnsResolver::class      => SystemDnsResolver::class,
        Enforcement::class      => DatabaseEnforcement::class,
        EndpointResolver::class => ConfiguredEndpointResolver::class,
        HandoffIssuer::class    => DatabaseHandoffStore::class,
    ];

    /** @var list<string> The abstracts registering binds, in order. */
    private const array BOUND = [
        'sso.default:' . Clock::class, Clock::class,
        'sso.default:' . HostResolver::class, HostResolver::class,
        'sso.default:' . Freshness::class, Freshness::class,
        'sso.default:' . EnforcementInheritance::class, EnforcementInheritance::class,
        'sso.default:' . EnforcementExemption::class, EnforcementExemption::class,
        'sso.default:' . SessionRevocation::class, SessionRevocation::class,
        'sso.default:' . ApplicationPolicy::class, ApplicationPolicy::class,
        'sso.default:' . RedirectUriResolver::class, RedirectUriResolver::class,
        'sso.default:' . Linker::class, Linker::class,
        'sso.default:' . LinkLimit::class, LinkLimit::class,
        'sso.default:' . ReauthenticationSessions::class, ReauthenticationSessions::class,
        'sso.default:' . LinkEligibility::class, LinkEligibility::class,
        'sso.default:' . LinkConfirmation::class, LinkConfirmation::class,
        'sso.default:' . LinkEmailMatcher::class, LinkEmailMatcher::class,
        'sso.default:' . PrincipalScope::class, PrincipalScope::class,
        'sso.default:' . TenantMembership::class, TenantMembership::class,
        'sso.default:' . EvidencePolicy::class, EvidencePolicy::class,
        'sso.default:' . ProviderSessionDeadline::class, ProviderSessionDeadline::class,
        'sso.default:' . SingleUseStore::class, SingleUseStore::class,
        'sso.default:' . SecretEncrypter::class, SecretEncrypter::class,
        'sso.default:' . Fetcher::class, Fetcher::class,
        'sso.default:' . AttemptLimiter::class, AttemptLimiter::class,
        'sso.default:' . DnsResolver::class, DnsResolver::class,
        'sso.default:' . Enforcement::class, Enforcement::class,
        'sso.default:' . EndpointResolver::class, EndpointResolver::class,
        'sso.default:' . HandoffIssuer::class, HandoffIssuer::class,
        DriverScope::class,
        ProtocolManager::class,
        StrandedTransactions::class,
        ConfigurationChecks::class,
        ConfigurationChecker::class,
    ];

    /**
     * Registering the provider merges the package's configuration under the
     * `sso` key and binds the contracts' defaults and the configuration
     * checker, and nothing else.
     *
     * @return void
     */
    public function testRegisteringMergesTheConfigurationAndBindsTheDefaults(): void
    {
        [$app, $config] = self::application();

        $before = array_keys($app->getBindings());

        (new SsoServiceProvider($app))->register();

        self::assertSame(['sso' => require dirname(__DIR__, 2) . '/config/sso.php'], $config->all());
        self::assertSame(self::BOUND, array_values(array_diff(array_keys($app->getBindings()), $before)));
    }

    /**
     * Each default is shared under its private key, a singleton default for the
     * process and a scoped one within its scope, while the contract itself is
     * shared by nothing; the protocol registry is a singleton, and the checker
     * is built afresh each time it is resolved.
     *
     * @return void
     */
    public function testEachDefaultIsSharedUnderItsKeyAndNeverByTheContract(): void
    {
        [$app] = self::application();

        (new SsoServiceProvider($app))->register();

        foreach ([...array_keys(self::SINGLETON_DEFAULTS), ...array_keys(self::SCOPED_DEFAULTS)] as $contract) {
            self::assertTrue($app->isShared('sso.default:' . $contract), $contract . '\'s default is not shared.');
            self::assertFalse($app->isShared($contract), $contract . ' is shared.');
        }

        self::assertTrue($app->isShared(ProtocolManager::class));
        self::assertFalse($app->isShared(ConfigurationChecker::class));
        self::assertNotSame($app->make(ConfigurationChecker::class), $app->make(ConfigurationChecker::class));
    }

    /**
     * Rows of `[contract, default]`: every seam whose default is a singleton.
     *
     * @return iterable<string, array{0: class-string, 1: class-string}>
     */
    public static function provideSingletonDefaults(): iterable
    {
        foreach (self::SINGLETON_DEFAULTS as $contract => $default) {
            yield $contract => [$contract, $default];
        }
    }

    /**
     * A singleton default is resolved through its private key, and the same
     * instance serves every scope.
     *
     * @param  class-string  $contract
     * @param  class-string  $default
     * @return void
     */
    #[DataProvider('provideSingletonDefaults')]
    public function testEachSingletonDefaultIsResolvedThroughItsKeyForEveryScope(string $contract, string $default): void
    {
        [$app] = self::application();

        (new SsoServiceProvider($app))->register();

        $first = $app->make($contract);

        self::assertInstanceOf($default, $first);
        self::assertSame($app->make('sso.default:' . $contract), $first);

        $app->forgetScopedInstances();

        self::assertSame($first, $app->make($contract));
    }

    /**
     * Rows of `[contract, default]`: every seam whose default is scoped.
     *
     * @return iterable<string, array{0: class-string, 1: class-string}>
     */
    public static function provideScopedDefaults(): iterable
    {
        foreach (self::SCOPED_DEFAULTS as $contract => $default) {
            yield $contract => [$contract, $default];
        }
    }

    /**
     * A scoped default is resolved through its private key, one instance within
     * a scope and a new one in the next.
     *
     * @param  class-string  $contract
     * @param  class-string  $default
     * @return void
     */
    #[DataProvider('provideScopedDefaults')]
    public function testEachScopedDefaultIsResolvedThroughItsKeyAndFreshPerScope(string $contract, string $default): void
    {
        [$app] = self::application();

        (new SsoServiceProvider($app))->register();

        $first = $app->make($contract);

        self::assertInstanceOf($default, $first);
        self::assertSame($app->make('sso.default:' . $contract), $first);
        self::assertSame($first, $app->make($contract));

        $app->forgetScopedInstances();

        $next = $app->make($contract);

        self::assertInstanceOf($default, $next);
        self::assertNotSame($first, $next);
    }

    /**
     * Rows of `[contract, how]`: every scoped seam, bound over by each kind of
     * binding an application makes.
     *
     * @return iterable<string, array{0: class-string, 1: string}>
     */
    public static function provideBindingsOverScopedSeams(): iterable
    {
        foreach (array_keys(self::SCOPED_DEFAULTS) as $contract) {
            foreach (['bind', 'singleton', 'scoped', 'instance'] as $how) {
                yield "{$contract} by {$how}" => [$contract, $how];
            }
        }
    }

    /**
     * What an application binds over a scoped seam after the provider
     * registers, and after the default was resolved, is what the seam answers
     * from then on: the contract is in no scope of the package's, so forgetting
     * the scoped instances never brings the default back.
     *
     * @param  class-string  $contract
     * @param  string  $how
     * @return void
     */
    #[DataProvider('provideBindingsOverScopedSeams')]
    public function testABindingOverAScopedSeamOutlivesEveryScope(string $contract, string $how): void
    {
        [$app] = self::application();

        (new SsoServiceProvider($app))->register();

        $default = $app->make($contract);
        $own     = self::createStub($contract);

        self::bindOver($app, $contract, $how, $own);

        for ($scope = 0; $scope < 2; $scope++) {
            $app->forgetScopedInstances();

            self::assertSame($own, $app->make($contract));
        }

        self::assertNotSame($default, $own);
        self::assertInstanceOf(self::SCOPED_DEFAULTS[$contract], $app->make('sso.default:' . $contract));
    }

    /**
     * Rows of `[contract]`: every seam.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideEverySeam(): iterable
    {
        foreach ([...array_keys(self::SINGLETON_DEFAULTS), ...array_keys(self::SCOPED_DEFAULTS)] as $contract) {
            yield $contract => [$contract];
        }
    }

    /**
     * A seam still bound to the package's default is the package's, before it
     * is resolved and after, in every scope.
     *
     * @param  class-string  $contract
     * @return void
     */
    #[DataProvider('provideEverySeam')]
    public function testASeamLeftToItsDefaultIsThePackages(string $contract): void
    {
        [$app] = self::application();

        (new SsoServiceProvider($app))->register();

        self::assertTrue(SsoServiceProvider::isPackageDefault($app, $contract));

        $app->make($contract);

        self::assertTrue(SsoServiceProvider::isPackageDefault($app, $contract));

        $app->forgetScopedInstances();
        $app->make($contract);

        self::assertTrue(SsoServiceProvider::isPackageDefault($app, $contract));
    }

    /**
     * Rows of `[contract, how]`: every seam, bound over by each kind of binding
     * an application makes.
     *
     * @return iterable<string, array{0: class-string, 1: string}>
     */
    public static function provideBindingsOverSeams(): iterable
    {
        foreach ([...array_keys(self::SINGLETON_DEFAULTS), ...array_keys(self::SCOPED_DEFAULTS)] as $contract) {
            foreach (['bind', 'singleton', 'scoped', 'instance', 'alias'] as $how) {
                yield "{$contract} by {$how}" => [$contract, $how];
            }
        }
    }

    /**
     * Once an application binds over a seam, whether or not the default was
     * resolved, the seam is no longer the package's default.
     *
     * @param  class-string  $contract
     * @param  string  $how
     * @return void
     */
    #[DataProvider('provideBindingsOverSeams')]
    public function testASeamBoundOverIsNotThePackages(string $contract, string $how): void
    {
        foreach ([false, true] as $resolveFirst) {
            [$app] = self::application();

            (new SsoServiceProvider($app))->register();

            if ($resolveFirst) {
                $app->make($contract);
            }

            self::bindOver($app, $contract, $how, self::createStub($contract));

            self::assertFalse(SsoServiceProvider::isPackageDefault($app, $contract));

            $app->make($contract);

            self::assertFalse(SsoServiceProvider::isPackageDefault($app, $contract));
        }
    }

    /**
     * A contract bound before the provider registers, or bound by nobody, is
     * not the package's default; the configuration checker the provider binds
     * is.
     *
     * @return void
     */
    public function testOnlyWhatTheProviderBindsIsThePackages(): void
    {
        [$app] = self::application();

        $app->bind(Clock::class, SystemClock::class);

        (new SsoServiceProvider($app))->register();

        self::assertFalse(SsoServiceProvider::isPackageDefault($app, Clock::class));
        self::assertFalse(SsoServiceProvider::isPackageDefault($app, LoggerInterface::class));
        self::assertTrue(SsoServiceProvider::isPackageDefault($app, ConfigurationChecker::class));
    }

    /**
     * A binding the application or another package made before the provider
     * registers is kept, never replaced by the package's default.
     *
     * @return void
     */
    public function testABindingMadeBeforeIsKept(): void
    {
        [$app] = self::application();

        $clock = new class implements Clock {
            /**
             * A fixed instant.
             *
             * @return \Carbon\CarbonImmutable
             */
            #[\Override]
            public function now(): CarbonImmutable
            {
                return CarbonImmutable::parse('2026-10-31T00:00:00Z');
            }
        };

        $resolver = new StubHostResolver;

        $app->instance(Clock::class, $clock);
        $app->instance(HostResolver::class, $resolver);

        (new SsoServiceProvider($app))->register();

        self::assertSame($clock, $app->make(Clock::class));
        self::assertSame($resolver, $app->make(HostResolver::class));
    }

    /**
     * The seams are every contract the provider binds: registering on an
     * application that binds nothing binds exactly these contracts.
     *
     * @return void
     */
    public function testTheSeamsAreEveryContractTheProviderBinds(): void
    {
        [$app] = self::application();

        (new SsoServiceProvider($app))->register();

        $bound = [];

        foreach (glob(dirname(__DIR__, 2) . '/src/Contracts/*.php') ?: [] as $file) {

            $contract = 'SineMacula\Laravel\Sso\Contracts\\' . basename($file, '.php');

            if (!$app->bound($contract)) {
                continue;
            }

            $bound[] = $contract;
        }

        self::assertSame(self::SEAMS, $bound);
    }

    /**
     * Rows of `[seam]`: every seam the provider binds a default for.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideSeams(): iterable
    {
        foreach (self::SEAMS as $seam) {
            yield $seam => [$seam];
        }
    }

    /**
     * Whatever the application or another package bound to a seam before the
     * provider registers is kept, for every seam, never replaced by the
     * package's default (FEATURES "Adaptable to each consumer").
     *
     * @param  class-string  $seam
     * @return void
     */
    #[DataProvider('provideSeams')]
    public function testEverySeamBoundBeforeIsKept(string $seam): void
    {
        [$app] = self::application();

        $bound = self::createStub($seam);

        $app->instance($seam, $bound);

        (new SsoServiceProvider($app))->register();

        self::assertSame($bound, $app->make($seam));
    }

    /**
     * An enforcement inheritance, exemption or session revocation the
     * application bound before the provider registers is kept (SSO-4.2,
     * SSO-4.4, SSO-4.5); without one, each default is a singleton.
     *
     * @return void
     */
    public function testAnEnforcementContractBoundBeforeIsKept(): void
    {
        [$app] = self::application();

        $inheritance = new OwnTenantInheritance;
        $exemption   = new NoExemptions;
        $revocation  = new NoSessionRevocation;

        $app->instance(EnforcementInheritance::class, $inheritance);
        $app->instance(EnforcementExemption::class, $exemption);
        $app->instance(SessionRevocation::class, $revocation);

        (new SsoServiceProvider($app))->register();

        self::assertSame($inheritance, $app->make(EnforcementInheritance::class));
        self::assertSame($exemption, $app->make(EnforcementExemption::class));
        self::assertSame($revocation, $app->make(SessionRevocation::class));

        [$fresh] = self::application();

        (new SsoServiceProvider($fresh))->register();

        self::assertInstanceOf(NoSessionRevocation::class, $fresh->make(SessionRevocation::class));
        self::assertSame($fresh->make(SessionRevocation::class), $fresh->make(SessionRevocation::class));
    }

    /**
     * Every package class that takes a PSR-3 logger is given `SanitizingLogger`
     * by a contextual binding, and `LoggerInterface` is never bound for the
     * whole application.
     *
     * @return void
     */
    public function testEveryClassThatLogsIsGivenTheSanitizingLogger(): void
    {
        [$app] = self::application();

        $logger = $app->getAlias(LoggerInterface::class);
        $before = $app->getBindings()[$logger] ?? null;

        (new SsoServiceProvider($app))->register();

        self::assertSame(
            [
                GuzzleFetcher::class,
                SystemDnsResolver::class,
                AssertionValidator::class,
                UnsolicitedResponses::class,
                MetadataRefresher::class,
                SamlMetadataSource::class,
                OidcMetadataSource::class,
                ProviderKeys::class,
                CallbackCompletion::class,
                ClaimsAssembler::class,
                Pruner::class,
                ExpiryNotifier::class,
                DomainRechecker::class,
            ],
            SsoServiceProvider::LOGGING_CLASSES,
        );

        foreach (SsoServiceProvider::LOGGING_CLASSES as $class) {
            self::assertSame(SanitizingLogger::class, $app->contextual[$class][$logger] ?? null);
        }

        self::assertSame($before, $app->getBindings()[$logger] ?? null);
        self::assertArrayNotHasKey(LoggerInterface::class, $app->getBindings());
    }

    /**
     * Every configuration check is registered under its subject, the
     * foundations' first.
     *
     * @return void
     */
    public function testEveryConfigurationCheckIsRegistered(): void
    {
        self::assertSame(
            [
                'features', 'extensions', 'storage', 'endpoints', 'applications', 'clock', 'secrets', 'fetcher', 'logging', 'rate_limits', 'freshness', 'keys',
                'mapping', 'domains', 'flows', 'linking', 'saml2', 'oidc', 'metadata', 'pruning', 'operations',
            ],
            array_keys(SsoServiceProvider::CONFIGURATION_CHECKS),
        );
    }

    /**
     * Bind the object over the contract the way given, as an application does.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  class-string  $contract
     * @param  string  $how
     * @param  object  $own
     * @return void
     */
    private static function bindOver(Application $app, string $contract, string $how, object $own): void
    {
        $build = static fn (): object => $own;

        match ($how) {
            'bind'      => $app->bind($contract, $build),
            'singleton' => $app->singleton($contract, $build),
            'scoped'    => $app->scoped($contract, $build),
            'instance'  => $app->instance($contract, $own),
            default     => self::aliasOver($app, $contract, $own),
        };
    }

    /**
     * Make the contract an alias of the object, held under a name of the
     * application's.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  class-string  $contract
     * @param  object  $own
     * @return void
     */
    private static function aliasOver(Application $app, string $contract, object $own): void
    {
        $app->instance('application.' . $contract, $own);
        $app->alias('application.' . $contract, $contract);
    }

    /**
     * A bare application with an empty configuration repository and an
     * encrypter.
     *
     * @return array{0: \Illuminate\Foundation\Application, 1: \Illuminate\Config\Repository}
     */
    private static function application(): array
    {
        $app    = new Application(dirname(__DIR__, 2));
        $config = new ConfigRepository;

        $app->instance('config', $config);
        $app->instance('encrypter', new Encrypter(str_repeat('k', 32), 'AES-256-CBC'));

        return [$app, $config];
    }
}
