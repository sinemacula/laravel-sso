<?php

declare(strict_types = 1);

namespace Tests\Feature\Config;

use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
use SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Fixtures\Config\DirectoryCheck;
use Tests\Fixtures\Config\DirectoryServiceProvider;
use Tests\TestCase;

/**
 * Feature tests for a configuration check a composing package adds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationChecks::class)]
#[CoversClass(SsoServiceProvider::class)]
final class AddedConfigurationChecksTest extends TestCase
{
    /** @var string The problem the added check reports, under its subject. */
    private const string PROBLEM = '[directory] `directory.revocation` must be set.';

    /**
     * The registry is one instance that starts with the package's own checks.
     *
     * @return void
     */
    public function testTheRegistryIsTheApplicationsOwn(): void
    {
        $checks = $this->application()->make(ConfigurationChecks::class);

        self::assertSame($checks, $this->application()->make(ConfigurationChecks::class));
        self::assertSame(SsoServiceProvider::CONFIGURATION_CHECKS, $checks->all());
    }

    /**
     * Whether the registry is resolved before or after the composing provider
     * registers.
     *
     * @return iterable<string, array{bool}>
     */
    public static function registrationOrders(): iterable
    {
        yield 'the registry resolved first' => [true];
        yield 'the provider registered first' => [false];
    }

    /**
     * The checker runs the added check once, after the package's own.
     *
     * @param  bool  $resolvedFirst
     * @return void
     */
    #[DataProvider('registrationOrders')]
    public function testTheCheckerRunsTheAddedCheckAfterThePackagesOwn(bool $resolvedFirst): void
    {
        $app = $this->application();

        $app->forgetInstance(ConfigurationChecks::class);

        if ($resolvedFirst) {
            $app->make(ConfigurationChecks::class);
        }

        $app->register(DirectoryServiceProvider::class);

        self::assertSame(
            [...SsoServiceProvider::CONFIGURATION_CHECKS, 'directory' => DirectoryCheck::class],
            $app->make(ConfigurationChecks::class)->all(),
        );
        self::assertSame(
            [...array_keys(SsoServiceProvider::CONFIGURATION_CHECKS), 'directory'],
            array_keys($app->make(ConfigurationChecker::class)->report()),
        );
    }

    /**
     * Outside the console, the added check's problem stops the boot.
     *
     * @return void
     */
    public function testBootingOutsideTheConsoleFailsOnTheAddedChecksProblem(): void
    {
        $app = $this->servingARequest();

        config()->set('sso.features.oidc', true);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('- ' . self::PROBLEM);

        (new SsoServiceProvider($app))->boot();
    }

    /**
     * An added check that does not apply never fails the boot.
     *
     * @return void
     */
    public function testBootingWithThePackageOffSkipsTheAddedCheck(): void
    {
        $app = $this->servingARequest();

        (new SsoServiceProvider($app))->boot();

        self::assertNull($app->make(ConfigurationChecker::class)->report()['directory']);
    }

    /**
     * In the console, the added check's problem fails a worker command as it
     * starts.
     *
     * @return void
     */
    public function testAWorkerCommandFailsToStartOnTheAddedChecksProblem(): void
    {
        $app = $this->application();

        $app->register(DirectoryServiceProvider::class);

        config()->set('sso.features.oidc', true);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('- ' . self::PROBLEM);

        $app->make(Dispatcher::class)->dispatch(new CommandStarting('queue:work', new ArrayInput([]), new BufferedOutput));
    }

    /**
     * `sso:check` reports the added check under its subject.
     *
     * @return void
     */
    public function testTheCheckCommandReportsTheAddedCheck(): void
    {
        $this->application()->register(DirectoryServiceProvider::class);

        self::assertContains('[directory] not enabled', $this->check());

        config()->set('sso.features.oidc', true);

        self::assertContains(self::PROBLEM, $this->check());

        config()->set('directory.revocation', 'sessions');

        self::assertContains('[directory] OK', $this->check());
    }

    /**
     * The test application.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function application(): Application
    {
        /** @var \Illuminate\Foundation\Application */
        return $this->app;
    }

    /**
     * The test application with the composing provider registered, serving a
     * request.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function servingARequest(): Application
    {
        $app = $this->application();

        $app->register(DirectoryServiceProvider::class);

        (new \ReflectionProperty(Application::class, 'isRunningInConsole'))->setValue($app, false);

        return $app;
    }

    /**
     * The lines `sso:check` prints.
     *
     * @return list<string>
     */
    private function check(): array
    {
        Artisan::call('sso:check');

        return array_values(array_map(trim(...), array_filter(explode("\n", Artisan::output()), static fn (string $line): bool => trim($line) !== '')));
    }
}
