<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Composer\InstalledVersions;
use Illuminate\Config\Repository;
use Illuminate\Console\Application as Console;
use Illuminate\Container\Container;
use Illuminate\Database\DatabaseServiceProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Encryption\EncryptionServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Facade;
use Monolog\Handler\NullHandler;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FrozenClock;

/**
 * The minimal application a validator needs, for a bench's prepared fixtures:
 * the package's provider, its connections and keys tables in an in-memory
 * SQLite database of its own, whatever `DB_CONNECTION` says, an encrypter, a
 * log channel that writes nowhere, a frozen clock, and a fetcher with no
 * answers, so a bench that reached for the network would be refused rather than
 * time it.
 *
 * It is the only code the benches share. `SineMacula\Laravel\Sso\Testing`
 * builds what each validates; a bench builds that here once, in its
 * `#[BeforeMethods]`, so no bench times key generation, DNS or HTTP. What a
 * validator reads of the connection and its keys is part of what it costs, on
 * that one local database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BenchApplication
{
    /** @var string The instant every bench's clock holds. */
    public const string NOW = '2026-11-01T09:30:00Z';

    /** @var string The service provider's base URL. */
    private const string BASE_URL = 'https://sp.example.test';

    /** @var list<string> The shipped migrations of the tables a validator reads. */
    private const array MIGRATIONS = [
        '2026_11_01_000000_create_sso_connections_table.php',
        '2026_11_01_000001_create_sso_keys_table.php',
    ];

    /** @var list<string> The features a bench's connections run under. */
    private const array FEATURES = ['saml2', 'oidc', 'encrypted_assertions'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Build and boot the application, make it the current one, and create the
     * tables.
     *
     * @return \Illuminate\Foundation\Application
     */
    public static function boot(): Application
    {
        $app = new Application(dirname(__DIR__, 2));

        $app->instance('config', new Repository(self::configuration()));

        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);

        $app->register(DatabaseServiceProvider::class);
        $app->register(EncryptionServiceProvider::class);
        $app->register(SsoServiceProvider::class);

        $app->instance(Clock::class, new FrozenClock(self::NOW));
        $app->instance(Fetcher::class, new FakeFetcher);

        $app->boot();

        foreach (self::FEATURES as $feature) {
            $app->make('config')->set("sso.features.{$feature}", true);
        }

        $app->make('config')->set('sso.endpoints.base_url', self::BASE_URL);

        foreach (self::MIGRATIONS as $migration) {
            self::migration($migration)->up(); // @phpstan-ignore method.notFound
        }

        return $app;
    }

    /**
     * Forget the current application, so what runs next starts with none: its
     * connections closed, and the models, facades and console no longer bound
     * to it.
     *
     * @return void
     */
    public static function forget(): void
    {
        $app = Container::getInstance();

        foreach ($app->bound('db') ? $app->make('db')->getConnections() : [] as $connection) {
            $connection->disconnect();
        }

        Model::clearBootedModels();
        Model::unsetConnectionResolver();
        Model::unsetEventDispatcher();
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        Console::forgetBootstrappers();
        Container::setInstance(null);
    }

    /**
     * Make and save an enabled connection of a fixed tenant.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    public static function connection(array $attributes): Connection
    {
        $connection = new Connection;

        $connection->forceFill($attributes + ['tenant_id' => 'tenant-1', 'display_name' => 'Bench', 'enabled' => true])->save();

        return $connection;
    }

    /**
     * The parameter set that records the versions of the packages named in a
     * bench's report: one set, named by them, each package by its version.
     *
     * @param  string  ...$packages
     * @return array<string, array<string, string>>
     */
    public static function versions(string ...$packages): array
    {
        $versions = [];

        foreach ($packages as $package) {
            $versions[$package] = InstalledVersions::getPrettyVersion($package) ?? 'unknown';
        }

        $names = array_map(static fn (string $package, string $version): string => "{$package} {$version}", array_keys($versions), $versions);

        return [implode(', ', $names) => $versions];
    }

    /**
     * The configuration an application needs before the package's merges in.
     *
     * @return array<string, mixed>
     */
    private static function configuration(): array
    {
        return [
            'app' => [
                'key'    => 'base64:' . base64_encode('laravel-sso bench key of 32 byte'),
                'cipher' => 'AES-256-CBC',
            ],
            'database' => [
                'default'     => 'bench',
                'connections' => ['bench' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']],
            ],
            'logging' => [
                'default'  => 'null',
                'channels' => ['null' => ['driver' => 'monolog', 'handler' => NullHandler::class]],
            ],
        ];
    }

    /**
     * The shipped migration of the name.
     *
     * @param  string  $name
     * @return \Illuminate\Database\Migrations\Migration
     *
     * @SuppressWarnings("php:S4833")
     * @SuppressWarnings("php:S2003")
     */
    private static function migration(string $name): Migration
    {
        return require dirname(__DIR__, 2) . '/database/migrations/' . $name;
    }
}
