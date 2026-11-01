<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso;

use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Applications\ConfiguredApplicationPolicy;
use SineMacula\Laravel\Sso\Applications\ConfiguredRedirectUriResolver;
use SineMacula\Laravel\Sso\Clock\ClockCheck;
use SineMacula\Laravel\Sso\Clock\SystemClock;
use SineMacula\Laravel\Sso\Config\Checks\ApplicationsCheck;
use SineMacula\Laravel\Sso\Config\Checks\EndpointsCheck;
use SineMacula\Laravel\Sso\Config\Checks\ExtensionsCheck;
use SineMacula\Laravel\Sso\Config\Checks\FeaturesCheck;
use SineMacula\Laravel\Sso\Config\Checks\StorageCheck;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Connections\MappingCheck;
use SineMacula\Laravel\Sso\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Sso\Console\RecheckDomainsCommand;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
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
use SineMacula\Laravel\Sso\Domains\DomainsCheck;
use SineMacula\Laravel\Sso\Domains\SystemDnsResolver;
use SineMacula\Laravel\Sso\Endpoints\ConfiguredEndpointResolver;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Enforcement\NoExemptions;
use SineMacula\Laravel\Sso\Enforcement\OwnTenantInheritance;
use SineMacula\Laravel\Sso\Fetching\FetcherCheck;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use SineMacula\Laravel\Sso\Fetching\SystemHostResolver;
use SineMacula\Laravel\Sso\Flows\FlowsCheck;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Freshness\FreshnessCheck;
use SineMacula\Laravel\Sso\Freshness\RefusingFreshness;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Keys\KeysCheck;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Links\OneLinkPerConnection;
use SineMacula\Laravel\Sso\Logging\LoggingCheck;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitsCheck;
use SineMacula\Laravel\Sso\Results\ProviderDeadlineLimitsSession;
use SineMacula\Laravel\Sso\Revocation\NoSessionRevocation;
use SineMacula\Laravel\Sso\Secrets\LaravelSecretEncrypter;
use SineMacula\Laravel\Sso\Secrets\SecretsCheck;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;

/**
 * Package service provider: registers the package's configuration, its
 * contracts' defaults, its translations, its publishing tags and console
 * command, and checks the configuration of what is enabled at boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SsoServiceProvider extends ServiceProvider
{
    /** @var array<string, class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>> Every configuration check, by the subject its problems are reported under, in the order they run. A part of the package that adds settings adds its check here. */
    public const array CONFIGURATION_CHECKS = [
        'features'     => FeaturesCheck::class,
        'extensions'   => ExtensionsCheck::class,
        'storage'      => StorageCheck::class,
        'endpoints'    => EndpointsCheck::class,
        'applications' => ApplicationsCheck::class,
        'clock'        => ClockCheck::class,
        'secrets'      => SecretsCheck::class,
        'fetcher'      => FetcherCheck::class,
        'logging'      => LoggingCheck::class,
        'rate_limits'  => RateLimitsCheck::class,
        'freshness'    => FreshnessCheck::class,
        'keys'         => KeysCheck::class,
        'mapping'      => MappingCheck::class,
        'domains'      => DomainsCheck::class,
        'flows'        => FlowsCheck::class,
    ];

    /** @var list<class-string> Every package class that takes a PSR-3 logger. Each is given `Logging\SanitizingLogger`, so nothing the package logs skips sanitisation and redaction (SSO-5.7, SSO-9.8); the application's own `LoggerInterface` binding is left alone. A part of the package that logs adds its class here. */
    public const array LOGGING_CLASSES = [
        GuzzleFetcher::class,
        SystemDnsResolver::class,
    ];

    /** @var list<string> The console commands that start long-running or scheduled work: the queue workers, Horizon, the scheduler and the Octane servers. Each is checked as it starts and refused on a problem, as a request is at boot (SSO-12.3); every other command runs, so a misconfigured application can still run `sso:check`, its migrations and the commands that repair it. */
    public const array WORKER_COMMANDS = [
        'queue:work',
        'queue:listen',
        'horizon',
        'horizon:supervisor',
        'horizon:work',
        'schedule:run',
        'schedule:work',
        'schedule:test',
        'octane:start',
        'octane:frankenphp',
        'octane:roadrunner',
        'octane:swoole',
    ];

    /** @var list<string> File names of the shipped migrations, published under the `sso-migrations` tag and never run from the package (SSO-11.7). */
    private const array MIGRATIONS = [
        '2026_10_31_000000_create_sso_single_use_keys_table.php',
        '2026_10_31_000001_create_sso_rate_limits_table.php',
        '2026_11_01_000000_create_sso_connections_table.php',
        '2026_11_01_000001_create_sso_keys_table.php',
        '2026_11_02_000000_create_sso_domains_table.php',
        '2026_11_02_000001_create_sso_enforcement_table.php',
        '2026_11_03_000000_create_sso_links_table.php',
        '2026_11_03_000001_create_sso_authorization_requests_table.php',
        '2026_11_03_000002_create_sso_handoff_codes_table.php',
    ];

    /** @var list<class-string<\Illuminate\Console\Command>> The package's console commands, registered in the console only. */
    private const array COMMANDS = [
        CheckConfigurationCommand::class,
        RecheckDomainsCommand::class,
    ];

    /**
     * Register the configuration and the contracts' defaults.
     *
     * Every binding is a default: one the application or another package made
     * before this provider registers is kept, and one made after replaces it,
     * as any later binding does. A default that holds nothing between calls is
     * a singleton; one that reads configuration or a connection is scoped, so
     * nothing of one request or job outlives it under Octane or a queue worker
     * (SSO-11.2). Each default fails closed: the freshness contract's refuses
     * every operation (SSO-2.12); the DNS resolver's answers `lookup_failed`
     * whenever the system resolver cannot answer (SSO-3.2); enforcement is read
     * from the write connection on every question, inheritance applies each
     * tenant's own setting, nobody is exempt (SSO-4.1, SSO-4.2, SSO-4.4); the
     * session revocation revokes nothing, since the package keeps no sessions,
     * which its documentation says (SSO-4.5); an application allows external
     * sign-in only when its configuration says so, its redirect URI and the
     * endpoints are the configured ones, never the request's (SSO-5.1,
     * SSO-5.5); nothing is linked, an identity holds one link per connection,
     * and no session is found for reauthentication (SSO-8.3, SSO-8.4,
     * SSO-5.10); the provider's session deadline limits the application's
     * (SSO-6.10); and handoff codes are the package's own (SSO-9.2). The
     * protocol registry is a singleton that builds its drivers with the
     * application serving (see `ProtocolManager::driver()`). Each is resolved
     * only when first used. Every package class that logs is given
     * `SanitizingLogger` by a contextual binding, never by binding
     * `LoggerInterface` for the whole application.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/sso.php', 'sso');

        $this->app->singletonIf(Clock::class, SystemClock::class);
        $this->app->singletonIf(HostResolver::class, SystemHostResolver::class);
        $this->app->scopedIf(SingleUseStore::class, DatabaseSingleUseStore::class);
        $this->app->scopedIf(SecretEncrypter::class, LaravelSecretEncrypter::class);
        $this->app->scopedIf(Fetcher::class, GuzzleFetcher::class);
        $this->app->scopedIf(AttemptLimiter::class, DatabaseAttemptLimiter::class);
        $this->app->singletonIf(Freshness::class, RefusingFreshness::class);
        $this->app->scopedIf(DnsResolver::class, SystemDnsResolver::class);
        $this->app->scopedIf(Enforcement::class, DatabaseEnforcement::class);
        $this->app->singletonIf(EnforcementInheritance::class, OwnTenantInheritance::class);
        $this->app->singletonIf(EnforcementExemption::class, NoExemptions::class);
        $this->app->singletonIf(SessionRevocation::class, NoSessionRevocation::class);
        $this->app->singletonIf(ApplicationPolicy::class, ConfiguredApplicationPolicy::class);
        $this->app->singletonIf(RedirectUriResolver::class, ConfiguredRedirectUriResolver::class);
        $this->app->scopedIf(EndpointResolver::class, ConfiguredEndpointResolver::class);
        $this->app->singletonIf(Linker::class, NoLinks::class);
        $this->app->singletonIf(LinkLimit::class, OneLinkPerConnection::class);
        $this->app->singletonIf(ReauthenticationSessions::class, NoReauthenticationSessions::class);
        $this->app->singletonIf(ProviderSessionDeadline::class, ProviderDeadlineLimitsSession::class);
        $this->app->scopedIf(HandoffIssuer::class, DatabaseHandoffStore::class);
        $this->app->singletonIf(ProtocolManager::class);
        $this->app->when(self::LOGGING_CLASSES)->needs(LoggerInterface::class)->give(SanitizingLogger::class);
        $this->app->bindIf(
            ConfigurationChecker::class,
            static fn (Application $app): ConfigurationChecker => new ConfigurationChecker($app, self::CONFIGURATION_CHECKS),
        );
    }

    /**
     * Bootstrap the package.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->loadTranslationsFrom(__DIR__ . '/../lang', 'sso');

        $this->registerPublishing();
        $this->registerCommands();
        $this->checkConfiguration();
    }

    /**
     * Register the package's config, migration and translation publishing tags.
     *
     * @return void
     */
    private function registerPublishing(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/sso.php' => config_path('sso.php'),
        ], 'sso-config');

        $migrations = [];

        foreach (self::MIGRATIONS as $migration) {
            $migrations[__DIR__ . '/../database/migrations/' . $migration] = database_path('migrations/' . $migration);
        }

        $this->publishes($migrations, 'sso-migrations');

        $this->publishes([
            __DIR__ . '/../lang' => $this->app->langPath('vendor/sso'),
        ], 'sso-lang');
    }

    /**
     * Register the package's console commands when running in the console.
     *
     * @return void
     */
    private function registerCommands(): void
    {
        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->commands(self::COMMANDS);
    }

    /**
     * Check the configuration of what is enabled before the application does
     * any work with it, failing with every problem found (SSO-12.3): once the
     * application has booted to serve a request, and in the console as a worker
     * or scheduler command starts.
     *
     * @return void
     */
    private function checkConfiguration(): void
    {
        if ($this->app->runningInConsole()) {
            $this->checkConfigurationBeforeWork();

            return;
        }

        $this->app->booted(static function (Application $app): void {
            $app->make(ConfigurationChecker::class)->assertValid();
        });
    }

    /**
     * Check the configuration as each of `WORKER_COMMANDS` starts, so the
     * command fails with the `InvalidConfigurationException` before it takes a
     * job or runs a scheduled task. Every other command is left to run, with
     * `sso:check` to report the problems.
     *
     * The command is matched by the name Artisan resolved, so an alias or an
     * abbreviation of a worker command is checked as the command itself.
     *
     * @return void
     */
    private function checkConfigurationBeforeWork(): void
    {
        $app = $this->app;

        $app->make(Dispatcher::class)->listen(CommandStarting::class, static function (CommandStarting $event) use ($app): void {

            if (!in_array($event->command, self::WORKER_COMMANDS, true)) {
                return;
            }

            $app->make(ConfigurationChecker::class)->assertValid();
        });
    }
}
