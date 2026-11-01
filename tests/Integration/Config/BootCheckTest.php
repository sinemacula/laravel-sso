<?php

declare(strict_types = 1);

namespace Tests\Integration\Config;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Console\Kernel as FoundationKernel;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Exceptions\InvalidConfigurationException;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Tests\Concerns\ChecksTheFoundations;
use Tests\TestCase;

/**
 * Integration tests of the boot check on a whole application: booted to serve a
 * request, the configuration of what is enabled is checked once the application
 * has booted, a problem stops the boot with every problem listed, and a
 * well-configured or unused package boots; run from Artisan, a worker or
 * scheduler command is checked the same way as it starts, while every other
 * command runs (SSO-12.3).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoServiceProvider::class)]
#[CoversClass(ConfigurationChecker::class)]
final class BootCheckTest extends TestCase
{
    use ChecksTheFoundations;

    /** @var array<string, mixed> A package in use with its foundations well configured. */
    private const array IN_USE = [
        'sso.features.saml2'     => true,
        'sso.endpoints.base_url' => 'https://api.example.com',
        'sso.applications'       => ['web' => ['redirect_uri' => 'https://app.example.com/complete', 'external_sign_in' => true]],
    ];

    /** @var array<string, mixed> A package in use whose endpoints are not configured. */
    private const array MISCONFIGURED = [
        'sso.features.oidc' => true,
        'sso.applications'  => ['web' => ['redirect_uri' => 'https://app.example.com/complete']],
    ];

    /** @var string The start of the problems `MISCONFIGURED` is refused with. */
    private const string PROBLEM = "lists the same problems:\n- [endpoints] `sso.endpoints.base_url` must be an absolute https URL";

    /** @var array<string, mixed> The settings the next application boots with. */
    private static array $settings = [];

    /** @var bool Whether the next application runs every registered check, as a real one does, rather than the foundations' alone. */
    private static bool $everyCheck = false;

    /**
     * A misconfigured application fails to boot outside the console, with every
     * problem of what is enabled, and nothing of what is not.
     *
     * @return void
     */
    public function testAMisconfiguredApplicationFailsToBoot(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(
            "lists the same problems:\n"
            . '- [endpoints] `sso.endpoints.base_url` must be an absolute https URL (or http on 127.0.0.1 or [::1]) with no user information,'
            . " fragment or wildcard, or query.\n"
            . '- [applications] `sso.applications.web.discovery.fallback_url` must be an exact redirect URI',
        );

        $this->bootServingARequest([
            'sso.features.oidc'      => true,
            'sso.features.discovery' => true,
            'sso.applications'       => ['web' => ['redirect_uri' => 'https://app.example.com/complete', 'discovery' => ['enabled' => true]]],
        ]);
    }

    /**
     * An application with every feature off, and one whose enabled features are
     * well configured, boot outside the console.
     *
     * @return void
     */
    public function testAnUnusedOrWellConfiguredApplicationBoots(): void
    {
        $this->bootServingARequest([]);

        self::assertFalse($this->app?->runningInConsole());

        $this->bootServingARequest([
            'sso.features.saml2'     => true,
            'sso.endpoints.base_url' => 'https://api.example.com',
            'sso.applications'       => ['web' => ['redirect_uri' => 'https://app.example.com/complete', 'external_sign_in' => true]],
        ]);

        self::assertTrue($this->app?->isBooted());
    }

    /**
     * Through the checker the provider binds, with every registered check, a
     * package in use whose settings are all well configured (the shipped
     * defaults for everything but the foundations) boots outside the console.
     *
     * @return void
     */
    public function testAWellConfiguredApplicationBootsThroughEveryCheck(): void
    {
        $this->bootServingARequest(self::IN_USE, everyCheck: true);

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        self::assertFalse($app->runningInConsole());
        self::assertTrue($app->isBooted());
    }

    /**
     * Through the checker the provider binds, every registered check runs at
     * boot: a problem in each subject after the foundations is listed under its
     * subject, in the order the checks are registered.
     *
     * @return void
     */
    public function testEveryCheckRunsAtBoot(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(
            "lists the same problems:\n"
            . "- [clock] sso.clock.skew_seconds must be an integer from 0 to 300.\n"
            . "- [secrets] The default secret encrypter cannot encrypt and decrypt with `app.key`; set APP_KEY, or bind your own SecretEncrypter.\n"
            . '- [fetcher] sso.fetcher.refused_ranges.0 must be a CIDR range: an IPv4 address with /0 to /32, or an IPv6 address with /0 to /128.'
            . "\n- [logging] `sso.logging.channel` names the channel [missing], which is not configured in `logging.channels`.\n"
            . '- [rate_limits] `sso.rate_limits.redemption.per_ip` must be an array of `max` (1 to 1000000) and `decay_seconds` (1 to 86400).',
        );

        $this->bootServingARequest([
            ...self::IN_USE,
            'sso.clock.skew_seconds'            => 301,
            'app.key'                           => '',
            'sso.fetcher.refused_ranges'        => ['10.0.0.0/33'],
            'sso.logging.channel'               => 'missing',
            'sso.rate_limits.redemption.per_ip' => null,
        ], everyCheck: true);
    }

    /**
     * Run from Artisan in a misconfigured application, a queue worker and the
     * scheduler each fail as they start, with every problem of what is enabled,
     * before they take a job or run a task.
     *
     * @return void
     */
    public function testAWorkerCommandFailsToStartInAMisconfiguredApplication(): void
    {
        $this->bootInTheConsole(self::MISCONFIGURED);

        $commands = [
            'queue:work'   => ['connection' => 'sync', '--once' => true, '--sleep' => 0],
            'schedule:run' => [],
        ];

        foreach ($commands as $command => $parameters) {
            $failure = self::failureOf($command, $parameters);

            self::assertInstanceOf(InvalidConfigurationException::class, $failure, "{$command} started in a misconfigured application.");
            self::assertStringContainsString(self::PROBLEM, $failure->getMessage());
        }
    }

    /**
     * Run as `php artisan` runs it, a worker command named by an abbreviation
     * is checked as the command it resolves to.
     *
     * @return void
     */
    public function testAnAbbreviatedWorkerCommandFailsToStart(): void
    {
        $this->bootInTheConsole(self::MISCONFIGURED);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(self::PROBLEM);

        $this->app?->make(Kernel::class)->handle(
            new ArrayInput(['command' => 'queue:wor', 'connection' => 'sync', '--once' => true, '--sleep' => 0]),
            new BufferedOutput,
        );
    }

    /**
     * Run from Artisan in a misconfigured application, the commands that
     * inspect or repair it still run: `sso:check` lists the problems.
     *
     * @return void
     */
    public function testARecoveryCommandRunsInAMisconfiguredApplication(): void
    {
        $this->bootInTheConsole(self::MISCONFIGURED);

        self::assertSame(1, Artisan::call('sso:check'));
        self::assertStringContainsString('[endpoints] `sso.endpoints.base_url` must be an absolute https URL', Artisan::output());
        self::assertSame(0, Artisan::call('list'));
        self::assertSame(0, Artisan::call('config:show', ['config' => 'sso.features']));
    }

    /**
     * Run from Artisan in a well-configured application, a queue worker and the
     * scheduler start and do their work.
     *
     * @return void
     */
    public function testAWorkerCommandStartsInAWellConfiguredApplication(): void
    {
        $this->bootInTheConsole(self::IN_USE);

        self::assertSame(0, Artisan::call('queue:work', ['connection' => 'sync', '--once' => true, '--sleep' => 0]));
        self::assertSame(0, Artisan::call('schedule:run'));
    }

    /**
     * Bind the foundations' checks, unless the test runs every check, and apply
     * the settings the test boots with, before the package's provider registers
     * and boots.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        if (!self::$everyCheck) {
            self::checkTheFoundations($app);
        }

        config()->set(self::$settings);
    }

    /**
     * Boot a fresh application with the settings, as it boots to serve a
     * request rather than a console command, leaving a console application with
     * the defaults behind for the next test.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $everyCheck
     * @return void
     */
    private function bootServingARequest(array $settings, bool $everyCheck = false): void
    {
        self::$settings   = $settings;
        self::$everyCheck = $everyCheck;

        putenv('APP_RUNNING_IN_CONSOLE=false');

        try {
            $this->refreshApplication();
        } finally {
            putenv('APP_RUNNING_IN_CONSOLE');

            self::$settings   = [];
            self::$everyCheck = false;
        }
    }

    /**
     * Boot a fresh application with the settings, in the console, with Artisan
     * announcing each command as it starts, as it does outside the tests.
     *
     * @param  array<string, mixed>  $settings
     * @return void
     */
    private function bootInTheConsole(array $settings): void
    {
        self::$settings = $settings;

        try {
            $this->refreshApplication();
        } finally {
            self::$settings = [];
        }

        $kernel = $this->app?->make(Kernel::class);

        self::assertInstanceOf(FoundationKernel::class, $kernel);
        self::assertTrue($this->app?->runningInConsole());

        $kernel->rerouteSymfonyCommandEvents();
        $kernel->setArtisan(null);
    }

    /**
     * What the command failed with when Artisan ran it, or `null` when it ran.
     *
     * @param  string  $command
     * @param  array<string, mixed>  $parameters
     * @return ?\Throwable
     */
    private static function failureOf(string $command, array $parameters): ?\Throwable
    {
        try {
            Artisan::call($command, $parameters);
        } catch (\Throwable $failure) {
            return $failure;
        }

        return null;
    }
}
