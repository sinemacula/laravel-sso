<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Clock\SystemClock;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\HostResolver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Fetching\GuzzleFetcher;
use SineMacula\Laravel\Sso\Fetching\SystemHostResolver;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Fixtures\Fetching\StubHostResolver;

/**
 * Unit tests for the package SsoServiceProvider, on a bare application with no
 * framework bootstrapping: what registering merges and binds, how each default
 * is shared, and that a binding made before is kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
final class SsoServiceProviderTest extends TestCase
{
    /** @var list<string> The abstracts registering binds, in order. */
    private const array BOUND = [
        Clock::class,
        HostResolver::class,
        SingleUseStore::class,
        SecretEncrypter::class,
        Fetcher::class,
        AttemptLimiter::class,
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
     * The clock and the host resolver hold nothing between calls and are
     * singletons, kept when the scoped instances are forgotten; every default
     * that reads configuration or a connection is shared too, within its scope
     * (the feature tests show each is rebuilt for the next request or job); the
     * checker is built afresh each time it is resolved.
     *
     * @return void
     */
    public function testEachDefaultIsSharedAsItsStateAllows(): void
    {
        [$app] = self::application();

        (new SsoServiceProvider($app))->register();

        foreach ([Clock::class, HostResolver::class, SingleUseStore::class, SecretEncrypter::class, Fetcher::class, AttemptLimiter::class] as $abstract) {
            self::assertTrue($app->isShared($abstract), $abstract . ' is not shared.');
        }

        $clock    = $app->make(Clock::class);
        $resolver = $app->make(HostResolver::class);

        self::assertInstanceOf(SystemClock::class, $clock);
        self::assertInstanceOf(SystemHostResolver::class, $resolver);

        $app->forgetScopedInstances();

        self::assertSame($clock, $app->make(Clock::class));
        self::assertSame($resolver, $app->make(HostResolver::class));
        self::assertFalse($app->isShared(ConfigurationChecker::class));
        self::assertNotSame($app->make(ConfigurationChecker::class), $app->make(ConfigurationChecker::class));
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

        self::assertSame([GuzzleFetcher::class], SsoServiceProvider::LOGGING_CLASSES);

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
            ['features', 'extensions', 'storage', 'endpoints', 'applications', 'clock', 'secrets', 'fetcher', 'logging', 'rate_limits'],
            array_keys(SsoServiceProvider::CONFIGURATION_CHECKS),
        );
    }

    /**
     * A bare application with an empty configuration repository.
     *
     * @return array{0: \Illuminate\Foundation\Application, 1: \Illuminate\Config\Repository}
     */
    private static function application(): array
    {
        $app    = new Application(dirname(__DIR__, 2));
        $config = new ConfigRepository;

        $app->instance('config', $config);

        return [$app, $config];
    }
}
