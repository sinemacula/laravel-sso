<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso;

use Illuminate\Console\Events\CommandStarting;
use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Clock\ClockCheck;
use SineMacula\Laravel\Sso\Config\Checks\ApplicationsCheck;
use SineMacula\Laravel\Sso\Config\Checks\EndpointsCheck;
use SineMacula\Laravel\Sso\Config\Checks\ExtensionsCheck;
use SineMacula\Laravel\Sso\Config\Checks\FeaturesCheck;
use SineMacula\Laravel\Sso\Config\Checks\StorageCheck;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
use SineMacula\Laravel\Sso\Connections\MappingCheck;
use SineMacula\Laravel\Sso\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Sso\Console\ExpiringKeysCommand;
use SineMacula\Laravel\Sso\Console\PruneCommand;
use SineMacula\Laravel\Sso\Console\RecheckDomainsCommand;
use SineMacula\Laravel\Sso\Console\RefreshMetadataCommand;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\DomainsCheck;
use SineMacula\Laravel\Sso\Domains\SystemDnsResolver;
use SineMacula\Laravel\Sso\Events\StrandedTransactions;
use SineMacula\Laravel\Sso\Fetching\FetcherCheck;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use SineMacula\Laravel\Sso\Flows\FlowsCheck;
use SineMacula\Laravel\Sso\Freshness\FreshnessCheck;
use SineMacula\Laravel\Sso\Keys\ExpiryNotifier;
use SineMacula\Laravel\Sso\Keys\KeysCheck;
use SineMacula\Laravel\Sso\Linking\LinkingCheck;
use SineMacula\Laravel\Sso\Logging\LoggingCheck;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use SineMacula\Laravel\Sso\Metadata\MetadataCheck;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\OidcMetadataSource;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Metadata\SamlMetadataSource;
use SineMacula\Laravel\Sso\Operations\OperationsCheck;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCompletion;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClaimsAssembler;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcCheck;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Check;
use SineMacula\Laravel\Sso\Protocols\Saml2\UnsolicitedResponses;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Pruning\Pruner;
use SineMacula\Laravel\Sso\Pruning\PruningCheck;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitsCheck;
use SineMacula\Laravel\Sso\Secrets\SecretsCheck;
use SineMacula\Laravel\Sso\Support\PackageDefaults;

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
    /** @var array<string, class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>> The package's configuration checks, by the subject its problems are reported under, in the order they run; a part of the package that adds settings adds its check here. A composing package or the application adds its own through `Config\ConfigurationChecks`. */
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
        'linking'      => LinkingCheck::class,
        'saml2'        => Saml2Check::class,
        'oidc'         => OidcCheck::class,
        'metadata'     => MetadataCheck::class,
        'pruning'      => PruningCheck::class,
        'operations'   => OperationsCheck::class,
    ];

    /** @var list<class-string> Every package class that takes a PSR-3 logger. Each is given `Logging\SanitizingLogger`, so nothing the package logs skips sanitisation and redaction (SSO-5.7, SSO-9.8); the application's own `LoggerInterface` binding is left alone. A part of the package that logs adds its class here. */
    public const array LOGGING_CLASSES = [
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
        '2026_11_03_000003_create_sso_identity_guards_table.php',
    ];

    /** @var list<class-string<\Illuminate\Console\Command>> The package's console commands, registered in the console only. */
    private const array COMMANDS = [
        CheckConfigurationCommand::class,
        RecheckDomainsCommand::class,
        RefreshMetadataCommand::class,
        PruneCommand::class,
        ExpiringKeysCommand::class,
    ];

    /**
     * Register the configuration and the contracts' defaults.
     *
     * Every binding is a default: one the application or another package made
     * before this provider registers is kept, and one made after replaces it,
     * as any later binding does. Each default is bound under its private key
     * (`Support\PackageDefaults`), and the contract to a transient closure that
     * resolves that key, so the contract never holds an instance or a scope of
     * the package's and a binding made over it stays wholly its maker's. A
     * default that holds nothing between calls is a singleton; one that reads
     * configuration or a connection is scoped, so nothing of one request or job
     * outlives it under Octane or a queue worker (SSO-11.2). Each default fails
     * closed: the freshness contract's refuses every operation (SSO-2.12); the
     * DNS resolver's answers `lookup_failed` whenever the system resolver
     * cannot answer (SSO-3.2); enforcement is read from the write connection on
     * every question, inheritance applies each tenant's own setting, nobody is
     * exempt (SSO-4.1, SSO-4.2, SSO-4.4); the session revocation revokes
     * nothing, since the package keeps no sessions, which its documentation
     * says (SSO-4.5); an application allows external sign-in only when its
     * configuration says so, its redirect URI and the endpoints are the
     * configured ones, never the request's (SSO-5.1, SSO-5.5); nothing is
     * linked, an identity holds one link per connection, and no session is
     * found for reauthentication (SSO-8.3, SSO-8.4, SSO-5.10); no identity may
     * link, no email matches, no principal set or membership is known, and no
     * evidence is accepted (SSO-8.5, SSO-8.7, SSO-8.8); the provider's session
     * deadline limits the application's (SSO-6.10); and handoff codes are the
     * package's own (SSO-9.2). The protocol registry is a singleton that builds
     * its drivers with the application serving, in its present scope (see
     * `ProtocolManager::driver()`). Each is resolved only when first used.
     * `Events\StrandedTransactions` is a singleton, never scoped, since the
     * listener the provider registers and the after-commit dispatch must share
     * its marks. Every package class that logs is given `SanitizingLogger` by a
     * contextual binding, never by binding `LoggerInterface` for the whole
     * application.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/sso.php', 'sso');

        foreach (PackageDefaults::SINGLETONS as $contract => $default) {
            $this->app->singleton(PackageDefaults::key($contract), $default);
            $this->app->bindIf($contract, self::forwardTo(PackageDefaults::key($contract)));
        }

        foreach (PackageDefaults::SCOPED as $contract => $default) {
            $this->app->scoped(PackageDefaults::key($contract), $default);
            $this->app->bindIf($contract, self::forwardTo(PackageDefaults::key($contract)));
        }

        foreach (PackageDefaults::SCOPED_STATE as $abstract) {
            $this->app->scoped($abstract);
        }

        $this->app->singletonIf(ProtocolManager::class);
        $this->app->singleton(StrandedTransactions::class);
        $this->app->when(self::LOGGING_CLASSES)->needs(LoggerInterface::class)->give(SanitizingLogger::class);
        $this->app->singleton(ConfigurationChecks::class, static fn (): ConfigurationChecks => new ConfigurationChecks(self::CONFIGURATION_CHECKS));
        $this->app->bindIf(
            ConfigurationChecker::class,
            static fn (Application $app): ConfigurationChecker => new ConfigurationChecker($app, $app->make(ConfigurationChecks::class)->all()),
        );
    }

    /**
     * Determine whether the contract is still bound to the package's default,
     * rather than to anything an application or another package bound over it.
     *
     * The package binds each contract to a closure the provider declares, and
     * never holds an instance under it, so an instance held, an alias, an
     * unbound contract and any other binding answer false.
     *
     * @param  \Illuminate\Container\Container  $container
     * @param  string  $contract
     * @return bool
     */
    public static function isPackageDefault(Container $container, string $contract): bool
    {
        $concrete = $container->getBindings()[$contract]['concrete'] ?? null;

        if (!$concrete instanceof \Closure || (new \ReflectionFunction($concrete))->getClosureScopeClass()?->getName() !== self::class) {
            return false;
        }

        return !$container->isShared($contract) && !$container->isAlias($contract);
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
        $this->markStrandedTransactions();
        $this->checkConfiguration();
    }

    /**
     * Return the closure a contract is bound to, resolving the private key of
     * its default in the container that resolves the contract.
     *
     * @param  string  $key
     * @return \Closure(\Illuminate\Contracts\Container\Container): mixed
     */
    private static function forwardTo(string $key): \Closure
    {
        return static fn (ContainerContract $app): mixed => $app->make($key);
    }

    /**
     * Mark the records a failed commit left behind when the next outermost
     * transaction begins on their connection, for the after-commit dispatch
     * (see `Events\StrandedTransactions`), as soon as the events dispatcher is
     * resolved. It is resolved here, as the application boots, so every request
     * and job the process serves shares it, an Octane sandbox included.
     *
     * @return void
     */
    private function markStrandedTransactions(): void
    {
        $stranded = $this->app->make(StrandedTransactions::class);

        $this->callAfterResolving('events', static function (Dispatcher $events) use ($stranded): void {
            $events->listen(TransactionBeginning::class, static function (TransactionBeginning $event) use ($stranded): void {
                self::markStranded($stranded, $event);
            });
        });
    }

    /**
     * Mark the records stranded on the connection when the transaction begun is
     * its outermost and a transactions manager is bound.
     *
     * @param  \SineMacula\Laravel\Sso\Events\StrandedTransactions  $stranded
     * @param  \Illuminate\Database\Events\TransactionBeginning  $event
     * @return void
     */
    private static function markStranded(StrandedTransactions $stranded, TransactionBeginning $event): void
    {
        if ($event->connection->transactionLevel() !== 1) {
            return;
        }

        // Not the container captured at boot: under Octane this is the sandbox.
        $container = Container::getInstance();
        $manager   = $container->bound('db.transactions') ? $container->make('db.transactions') : null;

        if (!$manager instanceof DatabaseTransactionsManager) {
            return;
        }

        $stranded->begun($event, $manager);
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
