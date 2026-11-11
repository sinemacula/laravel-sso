<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\HostResolver;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Events\StrandedTransactions;
use SineMacula\Laravel\Sso\Protocols\DriverScope;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use SineMacula\Laravel\Sso\Support\RequestState;

/**
 * Unit tests for `RequestState`: it forgets the package's scoped defaults and
 * its driver scope, and keeps the singleton defaults, the stranded
 * transactions, what the application scoped itself and what it bound over a
 * contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestState::class)]
final class RequestStateTest extends TestCase
{
    /** @var list<class-string> Every seam whose default is scoped. */
    private const array SCOPED = [
        SingleUseStore::class, SecretEncrypter::class, Fetcher::class, AttemptLimiter::class, DnsResolver::class,
        Enforcement::class, EndpointResolver::class, HandoffIssuer::class,
    ];

    /**
     * Each scoped default and the driver scope are built afresh after
     * `forget()`, through the contract and through the private key alike.
     *
     * @return void
     */
    public function testEachScopedDefaultAndTheDriverScopeAreForgotten(): void
    {
        $app = self::application();

        $before = self::resolve($app, [...self::SCOPED, DriverScope::class]);

        RequestState::forget($app);

        foreach (self::resolve($app, [...self::SCOPED, DriverScope::class]) as $abstract => $instance) {
            self::assertNotSame($before[$abstract], $instance, $abstract . ' was kept.');
            self::assertSame($instance, $app->make($abstract));
        }

        foreach (self::SCOPED as $contract) {
            self::assertSame($app->make($contract), $app->make('sso.default:' . $contract));
        }
    }

    /**
     * The singleton defaults, the protocol registry and the stranded
     * transactions outlive `forget()`.
     *
     * @return void
     */
    public function testTheSingletonsAndTheStrandedTransactionsAreKept(): void
    {
        $app = self::application();

        $kept = [Clock::class, HostResolver::class, Freshness::class, Linker::class, ProtocolManager::class, StrandedTransactions::class];

        $before = self::resolve($app, $kept);

        RequestState::forget($app);

        self::assertSame($before, self::resolve($app, $kept));
    }

    /**
     * What the application bound over a contract, and what it scoped itself, is
     * left as it was.
     *
     * @return void
     */
    public function testWhatTheApplicationBoundIsKept(): void
    {
        $app = self::application();

        $app->make(Fetcher::class);

        $fetcher = self::createStub(Fetcher::class);

        $app->instance(Fetcher::class, $fetcher);
        $app->scoped('application.state', static fn (): object => new \stdClass);

        $state = $app->make('application.state');

        RequestState::forget($app);

        self::assertSame($fetcher, $app->make(Fetcher::class));
        self::assertSame($state, $app->make('application.state'));
    }

    /**
     * Resolve each abstract, by the abstract.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  list<string>  $abstracts
     * @return array<string, mixed>
     */
    private static function resolve(Application $app, array $abstracts): array
    {
        $resolved = [];

        foreach ($abstracts as $abstract) {
            $resolved[$abstract] = $app->make($abstract);
        }

        return $resolved;
    }

    /**
     * A bare application with the provider registered.
     *
     * @return \Illuminate\Foundation\Application
     */
    private static function application(): Application
    {
        $app = new Application(dirname(__DIR__, 3));

        $app->instance('config', new ConfigRepository);
        $app->instance('encrypter', new Encrypter(str_repeat('k', 32), 'AES-256-CBC'));

        (new SsoServiceProvider($app))->register();

        return $app;
    }
}
