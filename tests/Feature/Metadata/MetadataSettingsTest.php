<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Metadata\MetadataCheck;
use SineMacula\Laravel\Sso\Metadata\MetadataSettings;
use Tests\TestCase;

/**
 * Feature tests for how the metadata refresh runs (SSO-2.8, SSO-11.12): each
 * default, each bound at, under and over, the backoff doubling to its most, the
 * stale limit's explicit none, and `[metadata]` checking each the same way,
 * only while the `metadata_refresh` feature is on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataSettings::class)]
#[CoversClass(MetadataCheck::class)]
final class MetadataSettingsTest extends TestCase
{
    /**
     * With nothing configured, each setting is its default.
     *
     * @return void
     */
    public function testEachSettingDefaults(): void
    {
        config()->set('sso.metadata', []);

        $settings = new MetadataSettings(config());

        self::assertSame([86400, 300, 21600, 2592000, 300], [
            $settings->refreshIntervalSeconds(), $settings->backoffInitialSeconds(), $settings->backoffMaxSeconds(),
            $settings->staleLimitSeconds(), $settings->claimSeconds(),
        ]);
    }

    /**
     * Rows of `[key, read, least, most]`: each bounded setting, what reads it,
     * and its bounds.
     *
     * @return iterable<string, array{0: string, 1: \Closure(\SineMacula\Laravel\Sso\Metadata\MetadataSettings): ?int, 2: int, 3: int}>
     */
    public static function provideSettings(): iterable
    {
        yield from [
            'interval'    => ['refresh_interval_seconds', static fn (MetadataSettings $settings): int => $settings->refreshIntervalSeconds(), 3600, 604800],
            'backoff'     => ['backoff_initial_seconds', static fn (MetadataSettings $settings): int => $settings->backoffInitialSeconds(), 60, 3600],
            'backoff max' => ['backoff_max_seconds', static fn (MetadataSettings $settings): int => $settings->backoffMaxSeconds(), 300, 86400],
            'stale limit' => ['stale_limit_seconds', static fn (MetadataSettings $settings): ?int => $settings->staleLimitSeconds(), 86400, 31536000],
            'claim'       => ['claim_seconds', static fn (MetadataSettings $settings): int => $settings->claimSeconds(), 30, 3600],
        ];
    }

    /**
     * Each setting is read at its bounds and refused one past either, naming
     * its key.
     *
     * @param  string  $key
     * @param  \Closure(\SineMacula\Laravel\Sso\Metadata\MetadataSettings): ?int  $read
     * @param  int  $least
     * @param  int  $most
     * @return void
     */
    #[DataProvider('provideSettings')]
    public function testEachSettingIsHeldToItsBounds(string $key, \Closure $read, int $least, int $most): void
    {
        $settings = new MetadataSettings(config());

        config()->set('sso.metadata.backoff_initial_seconds', $key === 'backoff_max_seconds' ? 300 : 60);

        foreach ([$least, $most, (string) $most] as $value) {
            config()->set('sso.metadata.' . $key, $value);

            self::assertSame((int) $value, $read($settings));
        }

        foreach ([$least - 1, $most + 1, 'x'] as $value) {
            config()->set('sso.metadata.' . $key, $value);

            try {
                $read($settings);
                self::fail("sso.metadata.{$key} accepted " . var_export($value, true) . '.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf('sso.metadata.%s must be an integer from %d to %d.', $key, $least, $most), $exception->getMessage());
            }
        }
    }

    /**
     * The longest backoff may not be shorter than the first.
     *
     * @return void
     */
    public function testTheLongestBackoffIsNeverShorterThanTheFirst(): void
    {
        config()->set('sso.metadata.backoff_initial_seconds', 600);
        config()->set('sso.metadata.backoff_max_seconds', 599);

        $this->expectExceptionObject(new \InvalidArgumentException('sso.metadata.backoff_max_seconds must be an integer from 600 to 86400.'));

        (new MetadataSettings(config()))->backoffMaxSeconds();
    }

    /**
     * Rows of `[failures, wait]`: failures in a row, and the wait before the
     * next attempt, under the defaults.
     *
     * @return iterable<string, array{0: int, 1: int}>
     */
    public static function provideBackoffs(): iterable
    {
        yield from [
            'none yet'  => [0, 300],
            'one'       => [1, 300],
            'two'       => [2, 600],
            'three'     => [3, 1200],
            'seven'     => [7, 19200],
            'eight'     => [8, 21600],
            'a hundred' => [100, 21600],
        ];
    }

    /**
     * The backoff doubles from the first wait with each failure in a row, up to
     * the longest.
     *
     * @param  int  $failures
     * @param  int  $wait
     * @return void
     */
    #[DataProvider('provideBackoffs')]
    public function testTheBackoffDoublesUpToTheLongest(int $failures, int $wait): void
    {
        self::assertSame($wait, (new MetadataSettings(config()))->backoffSeconds($failures));
    }

    /**
     * A stale limit of `0`, given explicitly, is none.
     *
     * @return void
     */
    public function testAStaleLimitOfZeroIsNone(): void
    {
        $settings = new MetadataSettings(config());

        foreach ([0, '0'] as $value) {
            config()->set('sso.metadata.stale_limit_seconds', $value);

            self::assertNull($settings->staleLimitSeconds());
        }
    }

    /**
     * `[metadata]` applies while the `metadata_refresh` feature is on or its
     * switch is malformed, and checks each setting.
     *
     * @return void
     */
    public function testTheCheckAppliesWithTheFeatureAndChecksEachSetting(): void
    {
        $check = new MetadataCheck(config());

        config()->set('sso.features.metadata_refresh', false);
        self::assertFalse($check->applies());

        config()->set('sso.features.metadata_refresh', 'maybe');
        self::assertTrue($check->applies());

        config()->set('sso.features.metadata_refresh', true);
        self::assertTrue($check->applies());
        self::assertSame([86400, 300, 21600, 2592000, 300], array_map(static fn (\Closure $check): mixed => $check(), $check->checks()));
    }
}
