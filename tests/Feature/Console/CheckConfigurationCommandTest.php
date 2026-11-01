<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Config\ConfigurationChecker;
use SineMacula\Laravel\Sso\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\ChecksTheFoundations;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `sso:check`: every registered subject reported as checked,
 * not enabled or with each of its problems, a non-zero exit on a problem, and
 * no database connection opened.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckConfigurationCommand::class)]
final class CheckConfigurationCommandTest extends TestCase
{
    use ChecksTheFoundations, RunsConfigurationChecks;

    /**
     * With every feature off, only the switches are checked, the rest reported
     * as not enabled, and the run passes without a query.
     *
     * @return void
     */
    public function testWithEveryFeatureOffOnlyTheSwitchesAreChecked(): void
    {
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame([
            '[features] OK',
            '[extensions] not enabled',
            '[storage] not enabled',
            '[endpoints] not enabled',
            '[applications] not enabled',
        ], $output);
        self::assertSame(0, $queries);
    }

    /**
     * With the package in use and well configured, every subject is checked and
     * passes.
     *
     * @return void
     */
    public function testAWellConfiguredPackagePasses(): void
    {
        $this->useThePackage();

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(['[features] OK', '[extensions] OK', '[storage] OK', '[endpoints] OK', '[applications] OK'], $output);
    }

    /**
     * Every problem is listed under its subject, the others still reported, and
     * the run fails.
     *
     * @return void
     */
    public function testEveryProblemIsListedAndTheRunFails(): void
    {
        $this->useThePackage();

        config()->set('sso.endpoints.base_url', null);
        config()->set('sso.storage.connection', 'missing');

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[features] OK',
            '[extensions] OK',
            '[storage] `sso.storage.connection` names the connection [missing], which is not configured in `database.connections`.',
            '[endpoints] `sso.endpoints.base_url` must be an absolute https URL (or http on 127.0.0.1 or [::1]) with no user information, fragment or wildcard, or query.',
            '[applications] OK',
        ], $output);
    }

    /**
     * Through the checker the provider binds, every registered subject is
     * checked, in order: a well-configured package in use passes each, and a
     * problem in each subject after the foundations is listed under it.
     *
     * @return void
     */
    public function testEveryRegisteredCheckRuns(): void
    {
        $this->checkEverything();
        $this->useThePackage();

        [$code, $output] = $this->check();

        self::assertSame(0, $code);
        self::assertSame(array_map(static fn (string $subject): string => "[{$subject}] OK", array_keys(SsoServiceProvider::CONFIGURATION_CHECKS)), $output);

        config()->set('sso.clock.skew_seconds', 301);
        config()->set('app.key', '');
        config()->set('sso.fetcher.refused_ranges', ['10.0.0.0/33']);
        config()->set('sso.logging.channel', 'missing');
        config()->set('sso.rate_limits.redemption.per_ip', null);
        config()->set('sso.freshness.max_age_seconds.connection_trust', 0);
        config()->set('sso.keys.rsa_bits', 2048);
        config()->set('sso.mapping.max_values', 0);
        config()->set('sso.domains.recheck_grace_seconds', -1);
        config()->set('sso.authorization_requests.ttl_seconds', 901);

        $this->app?->forgetInstance('encrypter');
        $this->app?->forgetScopedInstances();

        [$code, $output] = $this->check();

        self::assertSame(1, $code);
        self::assertSame([
            '[features] OK',
            '[extensions] OK',
            '[storage] OK',
            '[endpoints] OK',
            '[applications] OK',
            '[clock] sso.clock.skew_seconds must be an integer from 0 to 300.',
            '[secrets] The default secret encrypter cannot encrypt and decrypt with `app.key`; set APP_KEY, or bind your own SecretEncrypter.',
            '[fetcher] sso.fetcher.refused_ranges.0 must be a CIDR range: an IPv4 address with /0 to /32, or an IPv6 address with /0 to /128.',
            '[logging] `sso.logging.channel` names the channel [missing], which is not configured in `logging.channels`.',
            '[rate_limits] `sso.rate_limits.redemption.per_ip` must be an array of `max` (1 to 1000000) and `decay_seconds` (1 to 86400).',
            '[freshness] sso.freshness.max_age_seconds.connection_trust must be an integer from 1 to 3600.',
            '[keys] sso.keys.rsa_bits must be one of 3072, 4096.',
            '[mapping] sso.mapping.max_values must be an integer from 1 to 10000.',
            '[domains] sso.domains.recheck_grace_seconds must be an integer from 0 to 2592000.',
            '[flows] sso.authorization_requests.ttl_seconds must be an integer from 60 to 900.',
        ], $output);
    }

    /**
     * Bind the checker to the foundations' checks before the provider registers
     * its own.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        self::checkTheFoundations($app);
    }

    /**
     * Forget the foundations' checker and register the provider again, so the
     * checker is the one the provider binds, with every registered check.
     *
     * @return void
     */
    private function checkEverything(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $app->offsetUnset(ConfigurationChecker::class);

        (new SsoServiceProvider($app))->register();
    }

    /**
     * Run `sso:check` and return its exit code and the lines it printed.
     *
     * @return array{0: int, 1: list<string>}
     */
    private function check(): array
    {
        $code   = Artisan::call('sso:check');
        $output = array_values(array_filter(explode("\n", Artisan::output()), static fn (string $line): bool => trim($line) !== ''));

        return [$code, array_map(trim(...), $output)];
    }
}
