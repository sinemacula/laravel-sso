<?php

declare(strict_types = 1);

namespace Tests\Feature\Pruning;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Pruning\PruneSettings;
use SineMacula\Laravel\Sso\Pruning\PruningCheck;
use Tests\TestCase;

/**
 * Feature tests for the clean-up's settings and their boot check (SSO-11.11):
 * the shipped defaults, the defaults when nothing is set, both edges of each
 * range, what is refused, and the check judging as the settings do, while the
 * package is in use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneSettings::class)]
#[CoversClass(PruningCheck::class)]
final class PruneSettingsTest extends TestCase
{
    /**
     * The shipped configuration is a day's retention, a thousand rows a batch
     * and a hundred thousand a kind.
     *
     * @return void
     */
    public function testTheShippedDefaults(): void
    {
        $settings = app(PruneSettings::class);

        self::assertSame(86400, $settings->retentionSeconds());
        self::assertSame(1000, $settings->batchSize());
        self::assertSame(100000, $settings->maxRowsPerKind());
    }

    /**
     * A configuration published before the settings existed takes the same
     * defaults.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        config()->set('sso.pruning', []);

        $settings = app(PruneSettings::class);

        self::assertSame(PruneSettings::DEFAULT_RETENTION_SECONDS, $settings->retentionSeconds());
        self::assertSame(PruneSettings::DEFAULT_BATCH_SIZE, $settings->batchSize());
        self::assertSame(PruneSettings::DEFAULT_MAX_ROWS_PER_KIND, $settings->maxRowsPerKind());
    }

    /**
     * Rows of `[key, value, answer]`: what each setting accepts.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: int}>
     */
    public static function provideAcceptedValues(): iterable
    {
        yield 'retention, none' => ['retention_seconds', 0, 0];
        yield 'retention, most' => ['retention_seconds', 7776000, 7776000];
        yield 'retention, a string' => ['retention_seconds', '3600', 3600];
        yield 'batch, least' => ['batch_size', 1, 1];
        yield 'batch, most' => ['batch_size', 10000, 10000];
        yield 'batch, a string' => ['batch_size', '500', 500];
        yield 'cap, least' => ['max_rows_per_kind', 1, 1];
        yield 'cap, most' => ['max_rows_per_kind', 100000000, 100000000];
        yield 'cap, a string' => ['max_rows_per_kind', '5000', 5000];
    }

    /**
     * Each value within its range is taken.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $answer
     * @return void
     */
    #[DataProvider('provideAcceptedValues')]
    public function testAcceptsEachValueWithinItsRange(string $key, mixed $value, int $answer): void
    {
        config()->set("sso.pruning.{$key}", $value);

        self::assertSame($answer, self::read($key));
    }

    /**
     * Rows of `[key, value, message]`: what each setting refuses.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideRefusedValues(): iterable
    {
        $retention = 'sso.pruning.retention_seconds must be an integer from 0 to 7776000.';
        $batch     = 'sso.pruning.batch_size must be an integer from 1 to 10000.';
        $cap       = 'sso.pruning.max_rows_per_kind must be an integer from 1 to 100000000.';

        yield 'retention, negative' => ['retention_seconds', -1, $retention];
        yield 'retention, past' => ['retention_seconds', 7776001, $retention];
        yield 'retention, a word' => ['retention_seconds', 'a day', $retention];
        yield 'batch, none' => ['batch_size', 0, $batch];
        yield 'batch, past' => ['batch_size', 10001, $batch];
        yield 'batch, a fraction' => ['batch_size', 1.5, $batch];
        yield 'cap, none' => ['max_rows_per_kind', 0, $cap];
        yield 'cap, past' => ['max_rows_per_kind', 100000001, $cap];
        yield 'cap, null' => ['max_rows_per_kind', null, $cap];
    }

    /**
     * Each value outside its range fails closed, naming the key.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesEachValueOutsideItsRange(string $key, mixed $value, string $message): void
    {
        config()->set("sso.pruning.{$key}", $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::read($key);
    }

    /**
     * The check runs each setting as the clean-up reads it, once the package is
     * in use.
     *
     * @return void
     */
    public function testTheCheckJudgesEachSettingWhileThePackageIsInUse(): void
    {
        $check = app(PruningCheck::class);

        self::assertFalse($check->applies());

        config()->set('sso.features.oidc', true);

        self::assertTrue($check->applies());

        $checks = $check->checks();

        self::assertCount(3, $checks);
        self::assertSame(86400, $checks[0]());
        self::assertSame(1000, $checks[1]());
        self::assertSame(100000, $checks[2]());

        foreach (['retention_seconds', 'batch_size', 'max_rows_per_kind'] as $index => $key) {

            config()->set("sso.pruning.{$key}", -1);

            try {
                $checks[$index]();
                self::fail("The check of {$key} passed a malformed value.");
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString($key, $exception->getMessage());
            }
        }
    }

    /**
     * Read the setting.
     *
     * @param  string  $key
     * @return int
     */
    private static function read(string $key): int
    {
        $settings = app(PruneSettings::class);

        return match ($key) {
            'retention_seconds' => $settings->retentionSeconds(),
            'batch_size'        => $settings->batchSize(),
            default             => $settings->maxRowsPerKind(),
        };
    }
}
