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
 * Registers the package's configuration, defaults, translations, publishing
 * tags and commands, and checks the configuration at boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SsoServiceProvider extends ServiceProvider
{
    /** @var array<string, class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>> The configuration checks by subject, in run order. */
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

    /** @var list<class-string> Every package class that logs; each is given `Logging\SanitizingLogger` contextually. */
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

    /** @var list<string> Worker commands checked as they start; others run, so a misconfiguration can be repaired. */
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

    /** @var list<string> The shipped migrations, published and never run from the package. */
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
     * Register the configuration and the contracts' fail-closed defaults.
     *
     * Each contract forwards to its default's private key through a transient
     * closure, so a binding made over the contract stays wholly its maker's.
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
        // Never scoped: the listener and after-commit dispatch share its marks.
        $this->app->singleton(StrandedTransactions::class);
        $this->app->when(self::LOGGING_CLASSES)->needs(LoggerInterface::class)->give(SanitizingLogger::class);
        $this->app->singleton(ConfigurationChecks::class, static fn (): ConfigurationChecks => new ConfigurationChecks(self::CONFIGURATION_CHECKS));
        $this->app->bindIf(
            ConfigurationChecker::class,
            static fn (Application $app): ConfigurationChecker => new ConfigurationChecker($app, $app->make(ConfigurationChecks::class)->all()),
        );
    }

    /**
     * Determine whether the contract is still bound to the package's default.
     *
     * Only a non-shared closure declared by this provider counts; an instance,
     * alias or any other binding does not.
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
     * Return the closure that resolves the default's private key in the
     * resolving container.
     *
     * @param  string  $key
     * @return \Closure(\Illuminate\Contracts\Container\Container): mixed
     */
    private static function forwardTo(string $key): \Closure
    {
        return static fn (ContainerContract $app): mixed => $app->make($key);
    }

    /**
     * Mark records a failed commit left behind as the next outermost
     * transaction begins.
     *
     * Resolved at boot so every request and job, an Octane sandbox included,
     * shares it.
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
     * Mark the connection's stranded records when an outermost transaction
     * begins.
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
     * Check the configuration once booted for a request, or as a worker command
     * starts.
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
     * Check the configuration as each of `WORKER_COMMANDS` starts, before it
     * takes any work.
     *
     * Matched by the name Artisan resolved, so aliases and abbreviations are
     * caught.
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
