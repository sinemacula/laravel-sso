<?php

declare(strict_types = 1);

namespace Tests\Feature\Logging;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Logging\LoggingCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[logging]`: checked while the package is in use, the
 * shipped defaults passing, and each malformed setting, and an unknown channel,
 * reported with the message the logger would fail closed with, all in one run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LoggingCheck::class)]
final class LoggingCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /** @var string The problem of a malformed channel. */
    private const string CHANNEL = '`sso.logging.channel` must be the name of a channel in `logging.channels`, or null or empty for the default channel.';

    /** @var string The problem of a channel `logging.channels` does not configure. */
    private const string UNKNOWN = '`sso.logging.channel` names the channel [missing], which is not configured in `logging.channels`.';

    /** @var string The problem of a malformed diagnostic length. */
    private const string LENGTH = 'sso.logging.max_diagnostic_length must be an integer from 64 to 4096.';

    /** @var string The problem of malformed redacted keys. */
    private const string KEYS = '`sso.logging.redacted_keys` must be a list of key names, each holding a letter or a digit.';

    /**
     * Not checked while the package is not in use, however malformed; the
     * shipped defaults pass once it is.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        config()->set('sso.logging.channel', 'missing');
        config()->set('sso.logging.max_diagnostic_length', 1);
        config()->set('sso.logging.redacted_keys', 'token');

        self::assertNull($this->problemsOf(LoggingCheck::class));

        $this->useThePackage();
        config()->set('sso.logging', ['channel' => null, 'max_diagnostic_length' => 512, 'redacted_keys' => []]);

        self::assertSame([], $this->problemsOf(LoggingCheck::class));
    }

    /**
     * A malformed protocol switch counts as the package in use, so the logging
     * settings are checked rather than skipped.
     *
     * @return void
     */
    public function testAppliesOverAMalformedProtocolSwitch(): void
    {
        config()->set('sso.features.oidc', 'yes');
        config()->set('sso.logging.channel', 'missing');

        self::assertSame([self::UNKNOWN], $this->problemsOf(LoggingCheck::class));
    }

    /**
     * Settings that are not configured at all take the defaults and pass.
     *
     * @return void
     */
    public function testUnsetSettingsPass(): void
    {
        $this->useThePackage();

        config()->set('sso.logging', []);

        self::assertSame([], $this->problemsOf(LoggingCheck::class));
    }

    /**
     * Rows of `[key, value, problems]`: settings and what each reports.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: list<string>}>
     */
    public static function provideSettings(): iterable
    {
        yield from [
            'a configured channel'     => ['channel', 'single', []],
            'an empty channel'         => ['channel', '', []],
            'an unknown channel'       => ['channel', 'missing', [self::UNKNOWN]],
            'a malformed channel'      => ['channel', ['single'], [self::CHANNEL]],
            'the least length'         => ['max_diagnostic_length', 64, []],
            'the greatest length'      => ['max_diagnostic_length', '4096', []],
            'a length below the least' => ['max_diagnostic_length', 63, [self::LENGTH]],
            'a length past the most'   => ['max_diagnostic_length', 4097, [self::LENGTH]],
            'a malformed length'       => ['max_diagnostic_length', 'long', [self::LENGTH]],
            'added keys'               => ['redacted_keys', ['tenant_secret', 'X-Api-Key'], []],
            'keys as a string'         => ['redacted_keys', 'tenant_secret', [self::KEYS]],
            'an empty key'             => ['redacted_keys', ['tenant_secret', ''], [self::KEYS]],
            'a key that is not text'   => ['redacted_keys', [42], [self::KEYS]],
            'keys as a map'            => ['redacted_keys', ['a' => 'tenant_secret'], [self::KEYS]],
        ];
    }

    /**
     * Each setting reports exactly its problems.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideSettings')]
    public function testReportsEachProblem(string $key, mixed $value, array $problems): void
    {
        $this->useThePackage();

        config()->set('sso.logging.' . $key, $value);

        self::assertSame($problems, $this->problemsOf(LoggingCheck::class));
    }

    /**
     * Every malformed setting is reported in one run, in order.
     *
     * @return void
     */
    public function testReportsEveryProblemInOneRun(): void
    {
        $this->useThePackage();

        config()->set('sso.logging', ['channel' => 'missing', 'max_diagnostic_length' => 0, 'redacted_keys' => ['']]);

        self::assertSame([self::UNKNOWN, self::LENGTH, self::KEYS], $this->problemsOf(LoggingCheck::class));
    }
}
