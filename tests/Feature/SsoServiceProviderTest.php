<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Applications\ConfiguredApplicationPolicy;
use SineMacula\Laravel\Sso\Applications\ConfiguredRedirectUriResolver;
use SineMacula\Laravel\Sso\Clock\SystemClock;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\HostResolver;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Domains\SystemDnsResolver;
use SineMacula\Laravel\Sso\Endpoints\ConfiguredEndpointResolver;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\NoExemptions;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use SineMacula\Laravel\Sso\Fetching\SystemHostResolver;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Links\OneLinkPerConnection;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\Results\ProviderDeadlineLimitsSession;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Concerns\ChecksTheFoundations;
use Tests\Fixtures\Fetching\StubHostResolver;
use Tests\TestCase;

/**
 * Feature tests for the package SsoServiceProvider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
final class SsoServiceProviderTest extends TestCase
{
    use ChecksTheFoundations;

    /**
     * The fetcher the container builds logs through `SanitizingLogger`, while
     * the application's own logger is left as the application bound it.
     *
     * @return void
     */
    public function testTheFetcherLogsThroughTheSanitizingLogger(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app     = $this->app;
        $fetcher = $app->make(Fetcher::class);

        self::assertInstanceOf(GuzzleFetcher::class, $fetcher);
        self::assertInstanceOf(SanitizingLogger::class, (new \ReflectionProperty($fetcher, 'logger'))->getValue($fetcher));
        self::assertNotInstanceOf(SanitizingLogger::class, $app->make(LoggerInterface::class));
    }

    /**
     * The fetcher the container builds resolves host names with the container's
     * `HostResolver`: the system resolver by default, bound as a singleton, and
     * the application's own once it binds one.
     *
     * @return void
     */
    public function testTheFetcherResolvesHostsWithTheBoundResolver(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $resolverOf = static fn (object $fetcher): mixed => (new \ReflectionProperty($fetcher, 'resolver'))->getValue($fetcher);
        $default    = $app->make(HostResolver::class);

        self::assertInstanceOf(SystemHostResolver::class, $default);
        self::assertSame($default, $resolverOf($app->make(Fetcher::class)));

        $resolver = new StubHostResolver;

        $app->instance(HostResolver::class, $resolver);
        $app->forgetScopedInstances();

        self::assertSame($resolver, $resolverOf($app->make(Fetcher::class)));
    }

    /**
     * Each scoped contract with its default.
     *
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function scopedDefaults(): iterable
    {
        yield 'the single-use store' => [SingleUseStore::class, DatabaseSingleUseStore::class];
        yield 'the secret encrypter' => [SecretEncrypter::class, LaravelSecretEncrypter::class];
        yield 'the fetcher' => [Fetcher::class, GuzzleFetcher::class];
        yield 'the attempt limiter' => [AttemptLimiter::class, DatabaseAttemptLimiter::class];
        yield 'the DNS resolver' => [DnsResolver::class, SystemDnsResolver::class];
        yield 'the enforcement' => [Enforcement::class, DatabaseEnforcement::class];
        yield 'the endpoint resolver' => [EndpointResolver::class, ConfiguredEndpointResolver::class];
        yield 'the handoff issuer' => [HandoffIssuer::class, DatabaseHandoffStore::class];
    }

    /**
     * Each contract that reads configuration or a connection resolves to its
     * default, one instance within a request or job, and a new one once the
     * scoped instances are forgotten, as Octane and a queue worker do between
     * them, so nothing of one outlives it (SSO-11.2).
     *
     * @param  class-string  $abstract
     * @param  class-string  $default
     * @return void
     */
    #[DataProvider('scopedDefaults')]
    public function testEachScopedDefaultIsRebuiltForTheNextRequest(string $abstract, string $default): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app   = $this->app;
        $first = $app->make($abstract);

        self::assertInstanceOf($default, $first);
        self::assertSame($first, $app->make($abstract));

        $app->forgetScopedInstances();

        $next = $app->make($abstract);

        self::assertInstanceOf($default, $next);
        self::assertNotSame($first, $next);
    }

    /**
     * The clock and the host resolver hold nothing between calls, so the same
     * instance serves every request; the configuration checker is built afresh
     * each time it is resolved.
     *
     * @return void
     */
    public function testTheStatelessDefaultsOutliveARequestAndTheCheckerNever(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app      = $this->app;
        $clock    = $app->make(Clock::class);
        $resolver = $app->make(HostResolver::class);

        self::assertInstanceOf(SystemClock::class, $clock);

        $app->forgetScopedInstances();

        self::assertSame($clock, $app->make(Clock::class));
        self::assertSame($resolver, $app->make(HostResolver::class));
        self::assertNotSame($app->make(ConfigurationChecker::class), $app->make(ConfigurationChecker::class));
    }

    /**
     * Each stateless enforcement contract with its default.
     *
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function statelessEnforcementDefaults(): iterable
    {
        yield 'the inheritance' => [EnforcementInheritance::class, OwnTenantInheritance::class];
        yield 'the exemption' => [EnforcementExemption::class, NoExemptions::class];
        yield 'the session revocation' => [SessionRevocation::class, NoSessionRevocation::class];
    }

    /**
     * The enforcement inheritance, exemption and session revocation defaults
     * hold nothing, so one instance serves every request (SSO-4.2, SSO-4.4,
     * SSO-4.5).
     *
     * @param  class-string  $abstract
     * @param  class-string  $default
     * @return void
     */
    #[DataProvider('statelessEnforcementDefaults')]
    public function testEachStatelessEnforcementDefaultOutlivesARequest(string $abstract, string $default): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app   = $this->app;
        $first = $app->make($abstract);

        self::assertInstanceOf($default, $first);

        $app->forgetScopedInstances();

        self::assertSame($first, $app->make($abstract));
    }

    /**
     * Each stateless flow contract with its default.
     *
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function statelessFlowDefaults(): iterable
    {
        yield 'the application policy' => [ApplicationPolicy::class, ConfiguredApplicationPolicy::class];
        yield 'the redirect URI resolver' => [RedirectUriResolver::class, ConfiguredRedirectUriResolver::class];
        yield 'the linker' => [Linker::class, NoLinks::class];
        yield 'the link limit' => [LinkLimit::class, OneLinkPerConnection::class];
        yield 'the reauthentication sessions' => [ReauthenticationSessions::class, NoReauthenticationSessions::class];
        yield 'the provider session deadline' => [ProviderSessionDeadline::class, ProviderDeadlineLimitsSession::class];
    }

    /**
     * The flow defaults that hold nothing (the application policy, the redirect
     * URI resolver, the linker, the link limit, the reauthentication sessions
     * and the provider session deadline) are each one instance for every
     * request (SSO-11.2).
     *
     * @param  class-string  $abstract
     * @param  class-string  $default
     * @return void
     */
    #[DataProvider('statelessFlowDefaults')]
    public function testEachStatelessFlowDefaultOutlivesARequest(string $abstract, string $default): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app   = $this->app;
        $first = $app->make($abstract);

        self::assertInstanceOf($default, $first);

        $app->forgetScopedInstances();

        self::assertSame($first, $app->make($abstract));
    }

    /**
     * The package's configuration is merged under the `sso` key, with the
     * package's defaults.
     *
     * @return void
     */
    public function testThePackageConfigurationIsMergedUnderTheSsoKey(): void
    {
        $config = $this->app?->make(ConfigRepository::class);

        self::assertInstanceOf(ConfigRepository::class, $config);
        self::assertTrue($config->has('sso'));
        self::assertSame(require dirname(__DIR__, 2) . '/config/sso.php', $config->get('sso'));
    }

    /**
     * A value the application sets in its own `sso` configuration takes
     * precedence over the package's default.
     *
     * @return void
     */
    public function testTheApplicationsConfigurationTakesPrecedence(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app    = $this->app;
        $config = $app->make(ConfigRepository::class);

        $config->set('sso', ['application' => 'value']);

        (new SsoServiceProvider($app))->register();

        self::assertSame('value', $config->get('sso.application'));
    }

    /**
     * The `sso-config` publish group is registered with the framework's publish
     * registry.
     *
     * @return void
     */
    public function testConfigPublishingTagIsRegistered(): void
    {
        self::assertContains('sso-config', ServiceProvider::publishableGroups());
        self::assertContains('sso-migrations', ServiceProvider::publishableGroups());
        self::assertContains('sso-lang', ServiceProvider::publishableGroups());
    }

    /**
     * The config tag publishes the package's config file to the application's
     * `config/sso.php`.
     *
     * @return void
     */
    public function testConfigPublishingTagPublishesThePackageConfig(): void
    {
        $paths = [];

        foreach (ServiceProvider::pathsToPublish(SsoServiceProvider::class, 'sso-config') as $from => $to) {
            $paths[(string) realpath($from)] = $to;
        }

        self::assertSame([
            realpath(dirname(__DIR__, 2) . '/config/sso.php') => config_path('sso.php'),
        ], $paths);
    }

    /**
     * Booting outside the console registers no publish path, checked against an
     * emptied registry so the paths the test application's boot registered
     * cannot hide one.
     *
     * @return void
     */
    public function testNothingIsPublishedOutsideTheConsole(): void
    {
        $app = \Mockery::mock(Application::class)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturnFalse();

        [$publishes, $groups] = [ServiceProvider::$publishes, ServiceProvider::$publishGroups];

        ServiceProvider::$publishes     = [];
        ServiceProvider::$publishGroups = [];

        try {
            (new SsoServiceProvider($app))->boot();

            self::assertSame([], ServiceProvider::$publishes);
            self::assertSame([], ServiceProvider::$publishGroups);
        } finally {
            [ServiceProvider::$publishes, ServiceProvider::$publishGroups] = [$publishes, $groups];
        }
    }

    /**
     * The migrations tag publishes each shipped migration to the application's
     * `database/migrations`, under its own name, and the package runs none
     * itself (SSO-11.7).
     *
     * @return void
     */
    public function testMigrationsArePublishedAndNeverLoaded(): void
    {
        $paths = ServiceProvider::pathsToPublish(SsoServiceProvider::class, 'sso-migrations');

        self::assertSame([
            '2026_10_31_000000_create_sso_single_use_keys_table.php',
            '2026_10_31_000001_create_sso_rate_limits_table.php',
            '2026_11_01_000000_create_sso_connections_table.php',
            '2026_11_01_000001_create_sso_keys_table.php',
            '2026_11_02_000000_create_sso_domains_table.php',
            '2026_11_02_000001_create_sso_enforcement_table.php',
            '2026_11_03_000000_create_sso_links_table.php',
            '2026_11_03_000001_create_sso_authorization_requests_table.php',
            '2026_11_03_000002_create_sso_handoff_codes_table.php',
        ], array_map(basename(...), array_keys($paths)));

        foreach ($paths as $from => $to) {
            self::assertSame(realpath(dirname(__DIR__, 2) . '/database/migrations'), realpath(dirname($from)));
            self::assertSame(database_path('migrations/' . basename($from)), $to);
        }

        /** @var \Illuminate\Database\Migrations\Migrator $migrator */
        $migrator = $this->app?->make('migrator');

        $root = (string) realpath(dirname(__DIR__, 2));

        self::assertNotContains(realpath(dirname(__DIR__, 2) . '/database/migrations'), array_map(realpath(...), $migrator->paths()));
        self::assertSame([], array_values(array_filter(
            $migrator->paths(),
            static fn (string $path): bool => ($real = realpath($path)) !== false && str_starts_with($real, $root),
        )));
    }

    /**
     * The translations are loaded under the `sso` namespace and published to
     * the application's `lang/vendor/sso` for overrides.
     *
     * @return void
     */
    public function testTranslationsAreLoadedAndPublished(): void
    {
        /** @var \Illuminate\Translation\Translator $translator */
        $translator = $this->app?->make('translator');

        self::assertSame(realpath(dirname(__DIR__, 2)) . '/src/../lang', $translator->getLoader()->namespaces()['sso'] ?? null);

        $paths = ServiceProvider::pathsToPublish(SsoServiceProvider::class, 'sso-lang');

        self::assertSame([lang_path('vendor/sso')], array_values($paths));
        self::assertSame(dirname(__DIR__, 2) . '/src/../lang', (string) array_key_first($paths));
    }

    /**
     * `sso:check` is registered in the console.
     *
     * @return void
     */
    public function testTheCheckCommandIsRegistered(): void
    {
        self::assertArrayHasKey('sso:check', Artisan::all());
    }

    /**
     * `sso:domains:recheck` is registered in the console.
     *
     * @return void
     */
    public function testTheDomainRecheckCommandIsRegistered(): void
    {
        self::assertArrayHasKey('sso:domains:recheck', Artisan::all());
    }

    /**
     * Outside the console, booting checks the configuration of what is enabled:
     * with every feature off, or a well-configured package, it boots.
     *
     * @return void
     */
    public function testBootingOutsideTheConsolePassesAWellConfiguredPackage(): void
    {
        $app = $this->servingARequest();

        (new SsoServiceProvider($app))->boot();

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/complete']]);

        (new SsoServiceProvider($app))->boot();

        self::assertFalse($app->runningInConsole());
    }

    /**
     * Outside the console, booting fails with every problem of what is enabled.
     *
     * @return void
     */
    public function testBootingOutsideTheConsoleFailsOnAProblem(): void
    {
        $app = $this->servingARequest();

        config()->set('sso.features.oidc', true);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage("lists the same problems:\n- [endpoints] `sso.endpoints.base_url` must be an absolute https URL");

        (new SsoServiceProvider($app))->boot();
    }

    /**
     * In the console the boot check does not run, so a misconfigured
     * application can still run its commands; `sso:check` reports instead.
     *
     * @return void
     */
    public function testBootingInTheConsoleLeavesTheCheckToTheCommand(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        config()->set('sso.features', ['saml2' => 'on', 'misspelt' => true]);

        (new SsoServiceProvider($app))->boot();

        self::assertTrue($app->runningInConsole());
    }

    /**
     * Every command that starts long-running or scheduled work: the queue
     * workers, Horizon's master, supervisors and workers, the scheduler and the
     * Octane servers.
     *
     * @return iterable<string, array{string}>
     */
    public static function workerCommands(): iterable
    {
        $commands = [
            'queue:work', 'queue:listen', 'horizon', 'horizon:supervisor', 'horizon:work', 'schedule:run', 'schedule:work',
            'schedule:test', 'octane:start', 'octane:frankenphp', 'octane:roadrunner', 'octane:swoole',
        ];

        foreach ($commands as $command) {
            yield $command => [$command];
        }
    }

    /**
     * In the console, each command that starts long-running or scheduled work
     * fails as it starts with every problem of what is enabled, before it takes
     * a job or runs a task (SSO-12.3).
     *
     * @param  string  $command
     * @return void
     */
    #[DataProvider('workerCommands')]
    public function testAWorkerCommandFailsToStartOnAProblem(string $command): void
    {
        self::checkTheFoundations($this->consoleApplication());

        config()->set('sso.features.oidc', true);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage("lists the same problems:\n- [endpoints] `sso.endpoints.base_url` must be an absolute https URL");

        $this->startCommand($command);
    }

    /**
     * In the console, each command that starts long-running or scheduled work
     * starts with every feature off, and with a well-configured package.
     *
     * @param  string  $command
     * @return void
     */
    #[DataProvider('workerCommands')]
    public function testAWorkerCommandStartsWithAWellConfiguredPackage(string $command): void
    {
        self::checkTheFoundations($this->consoleApplication());

        $this->startCommand($command);

        config()->set('sso.features.oidc', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/complete']]);

        $this->startCommand($command);

        self::assertContains($command, SsoServiceProvider::WORKER_COMMANDS);
    }

    /**
     * Commands an application runs to inspect or repair itself.
     *
     * @return iterable<string, array{string}>
     */
    public static function recoveryCommands(): iterable
    {
        $commands = [
            'sso:check', 'migrate', 'migrate:status', 'migrate:rollback', 'migrate:fresh', 'vendor:publish', 'config:cache',
            'config:clear', 'config:show', 'cache:clear', 'optimize', 'optimize:clear', 'package:discover', 'list', 'help',
            'about', 'tinker',
        ];

        foreach ($commands as $command) {
            yield $command => [$command];
        }
    }

    /**
     * In the console, a command that repairs or inspects the application starts
     * whatever the configuration, so a misconfigured application can still run
     * `sso:check`, its migrations, and clear and rebuild its caches.
     *
     * @param  string  $command
     * @return void
     */
    #[DataProvider('recoveryCommands')]
    public function testARecoveryCommandStartsOnAProblem(string $command): void
    {
        self::checkTheFoundations($this->consoleApplication());

        config()->set('sso.features', ['oidc' => true, 'misspelt' => true]);

        $this->startCommand($command);

        self::assertNotContains($command, SsoServiceProvider::WORKER_COMMANDS);
    }

    /**
     * The test application, which runs in the console.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function consoleApplication(): Application
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        self::assertTrue($app->runningInConsole());

        return $app;
    }

    /**
     * Announce that the command is starting, as Artisan does once it has
     * resolved the command's name and before it runs it.
     *
     * @param  string  $command
     * @return void
     */
    private function startCommand(string $command): void
    {
        $this->consoleApplication()->make(Dispatcher::class)->dispatch(new CommandStarting($command, new ArrayInput([]), new BufferedOutput));
    }

    /**
     * The test application, checking the foundations' configuration alone and
     * reporting that it is not running in the console, as it does serving a
     * request.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function servingARequest(): Application
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        self::checkTheFoundations($app);

        (new \ReflectionProperty(Application::class, 'isRunningInConsole'))->setValue($app, false);

        return $app;
    }
}
