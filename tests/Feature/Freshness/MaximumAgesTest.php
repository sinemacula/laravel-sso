<?php

declare(strict_types = 1);

namespace Tests\Feature\Freshness;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\MaximumAges;
use Tests\TestCase;

/**
 * Feature tests for the freshness maximum ages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MaximumAges::class)]
final class MaximumAgesTest extends TestCase
{
    /**
     * The block, the default and the range are the documented ones.
     *
     * @return void
     */
    public function testTheBlockDefaultAndRange(): void
    {
        self::assertSame('sso.freshness.max_age_seconds', MaximumAges::BLOCK);
        self::assertSame(300, MaximumAges::DEFAULT_SECONDS);
        self::assertSame(1, MaximumAges::MIN_SECONDS);
        self::assertSame(3600, MaximumAges::MAX_SECONDS);
    }

    /**
     * The shipped configuration requires 300 seconds for every operation.
     *
     * @return void
     */
    public function testTheShippedAgesAreFiveMinutes(): void
    {
        foreach (FreshnessOperation::cases() as $operation) {
            self::assertSame(300, $this->ages()->for($operation), $operation->value);
        }
    }

    /**
     * An unconfigured age, block or section requires 300 seconds.
     *
     * @return void
     */
    public function testAnUnsetAgeIsTheDefault(): void
    {
        config()->set('sso.freshness.max_age_seconds', ['connection_trust' => 60]);

        self::assertSame(60, $this->ages()->for(FreshnessOperation::CONNECTION_TRUST));
        self::assertSame(300, $this->ages()->for(FreshnessOperation::CONNECTION_ENABLE));

        foreach ([['max_age_seconds' => []], [], null] as $section) {
            config()->set('sso.freshness', $section);

            foreach (FreshnessOperation::cases() as $operation) {
                self::assertSame(300, $this->ages()->for($operation), $operation->value);
            }
        }
    }

    /**
     * Each operation is read from its own key.
     *
     * @return void
     */
    public function testEachOperationReadsItsOwnKey(): void
    {
        $operations = FreshnessOperation::cases();

        foreach ($operations as $index => $operation) {
            config()->set('sso.freshness.max_age_seconds.' . $operation->configKey(), 60 + $index);
        }

        foreach ($operations as $index => $operation) {
            self::assertSame(60 + $index, $this->ages()->for($operation), $operation->value);
        }
    }

    /**
     * The age is read on each call.
     *
     * @return void
     */
    public function testReadsTheAgeOnEachCall(): void
    {
        $ages = $this->ages();

        config()->set('sso.freshness.max_age_seconds.link_create', 120);

        self::assertSame(120, $ages->for(FreshnessOperation::LINK_CREATE));

        config()->set('sso.freshness.max_age_seconds.link_create', 30);

        self::assertSame(30, $ages->for(FreshnessOperation::LINK_CREATE));
    }

    /**
     * Rows of `[value, seconds]`: ages accepted and the seconds each reads as.
     *
     * @return iterable<string, array{0: int|string, 1: int}>
     */
    public static function provideAcceptedAges(): iterable
    {
        yield from [
            'the least'                => [1, 1],
            'the default'              => [300, 300],
            'the greatest'             => [3600, 3600],
            'a digit string'           => ['600', 600],
            'the least as a string'    => ['1', 1],
            'the greatest as a string' => ['3600', 3600],
        ];
    }

    /**
     * Each accepted age reads as its seconds, for every operation.
     *
     * @param  int|string  $value
     * @param  int  $seconds
     * @return void
     */
    #[DataProvider('provideAcceptedAges')]
    public function testAcceptsEachAge(int|string $value, int $seconds): void
    {
        foreach (FreshnessOperation::cases() as $operation) {
            config()->set('sso.freshness.max_age_seconds.' . $operation->configKey(), $value);

            self::assertSame($seconds, $this->ages()->for($operation), $operation->value);
        }
    }

    /**
     * Rows of `[value]`: ages that are not an integer from 1 to 3600.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedAges(): iterable
    {
        yield from [
            'none'                  => [0],
            'past the ceiling'      => [3601],
            'negative'              => [-1],
            'negative default'      => [-300],
            'a float'               => [1.5],
            'a whole float'         => [300.0],
            'a decimal string'      => ['1.5'],
            'a zero string'         => ['0'],
            'a string past the cap' => ['3601'],
            'a negative string'     => ['-300'],
            'a signed string'       => ['+300'],
            'a padded string'       => ['0300'],
            'a spaced string'       => [' 300'],
            'an exponent string'    => ['3e2'],
            'a word'                => ['five minutes'],
            'an empty string'       => [''],
            'null'                  => [null],
            'true'                  => [true],
            'false'                 => [false],
            'an array'              => [[300]],
            'an empty array'        => [[]],
        ];
    }

    /**
     * Each malformed age fails closed, naming the operation's key and never the
     * value.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedAges')]
    public function testRefusesEachMalformedAge(mixed $value): void
    {
        foreach (FreshnessOperation::cases() as $operation) {
            $key = 'sso.freshness.max_age_seconds.' . $operation->configKey();

            config()->set($key, $value);

            try {
                $this->ages()->for($operation);
                self::fail("{$key} was accepted.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame("{$key} must be an integer from 1 to 3600.", $exception->getMessage());
            }
        }
    }

    /**
     * A malformed age fails only its own operation.
     *
     * @return void
     */
    public function testAMalformedAgeFailsOnlyItsOperation(): void
    {
        config()->set('sso.freshness.max_age_seconds.keys_rotate', 0);

        self::assertSame(300, $this->ages()->for(FreshnessOperation::CONNECTION_TRUST));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('sso.freshness.max_age_seconds.keys_rotate must be an integer from 1 to 3600.');

        $this->ages()->for(FreshnessOperation::KEYS_ROTATE);
    }

    /**
     * The maximum ages, read from the application's configuration.
     *
     * @return \SineMacula\Laravel\Sso\Freshness\MaximumAges
     */
    private function ages(): MaximumAges
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(MaximumAges::class);
    }
}
