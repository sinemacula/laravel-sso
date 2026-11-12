<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Metadata\MetadataCheck;
use SineMacula\Laravel\Sso\Metadata\MetadataSettings;
use Tests\TestCase;

/**
 * Feature tests for the metadata refresh settings and their boot check.
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
    /** @var string The problem of a queue timeout longer than the claim. */
    private const string TIMEOUT_PAST_CLAIM = 'sso.metadata.queue.timeout_seconds must not exceed sso.metadata.claim_seconds, so a refresh never outlives its claim.';

    /**
     * With nothing configured, each setting is its default.
     *
     * @return void
     */
    public function testEachSettingDefaults(): void
    {
        config()->set('sso.metadata', []);

        $settings = new MetadataSettings(config());

        self::assertSame([1048576, 86400, 300, 21600, 2592000, 300, null, null, 60, 1], [
            $settings->maxBytes(), $settings->refreshIntervalSeconds(), $settings->backoffInitialSeconds(), $settings->backoffMaxSeconds(),
            $settings->staleLimitSeconds(), $settings->claimSeconds(), $settings->queueConnection(), $settings->queueName(),
            $settings->timeoutSeconds(), $settings->tries(),
        ]);
    }

    /**
     * Rows of `[key, read, least, most]`: each bounded setting, its reader and
     * its bounds.
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
            'size cap'    => ['max_bytes', static fn (MetadataSettings $settings): int => $settings->maxBytes(), 65536, 268435456],
            'timeout'     => ['queue.timeout_seconds', static fn (MetadataSettings $settings): int => $settings->timeoutSeconds(), 30, 3600],
            'tries'       => ['queue.tries', static fn (MetadataSettings $settings): int => $settings->tries(), 1, 10],
        ];
    }

    /**
     * Each setting is read at its bounds and refused one past either.
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
        config()->set('sso.metadata.claim_seconds', $key === 'claim_seconds' ? 30 : 3600);

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
     * A queued refresh may not be allowed longer than its claim holds: at the
     * claim it is read, a second past it refused.
     *
     * @return void
     */
    public function testTheTimeoutNeverExceedsTheClaim(): void
    {
        $settings = new MetadataSettings(config());

        config()->set('sso.metadata.claim_seconds', 600);
        config()->set('sso.metadata.queue.timeout_seconds', 600);

        self::assertSame(600, $settings->timeoutSeconds());

        config()->set('sso.metadata.queue.timeout_seconds', 601);

        $this->expectExceptionObject(new \InvalidArgumentException(self::TIMEOUT_PAST_CLAIM));

        $settings->timeoutSeconds();
    }

    /**
     * Rows of `[metadata connection, default connection, timeout, retry after,
     * problem]`.
     *
     * @return iterable<string, array{0: ?string, 1: string, 2: int, 3: mixed, 4: ?string}>
     */
    public static function provideRetryAfters(): iterable
    {
        $past = 'sso.metadata.queue.timeout_seconds must be shorter than the retry_after of queue connection [%s], so a refresh still running is never reserved again.';

        yield from [
            'its own, one under'       => ['slow', 'sync', 599, 600, null],
            'its own, at it'           => ['slow', 'sync', 600, 600, sprintf($past, 'slow')],
            'its own, one over'        => ['slow', 'sync', 601, 600, sprintf($past, 'slow')],
            'the default, one under'   => [null, 'slow', 89, '90', null],
            'the default, at it'       => [null, 'slow', 90, '90', sprintf($past, 'slow')],
            'its own, none set'        => ['slow', 'slow', 3600, null, null],
            'its own over the default' => ['fast', 'slow', 600, 600, null],
        ];
    }

    /**
     * A queued refresh's timeout stays under its queue connection's
     * `retry_after`, when one is set.
     *
     * @param  ?string  $connection
     * @param  string  $default
     * @param  int  $timeout
     * @param  mixed  $retryAfter
     * @param  ?string  $problem
     * @return void
     */
    #[DataProvider('provideRetryAfters')]
    public function testTheTimeoutStaysUnderTheQueuesRetryAfter(?string $connection, string $default, int $timeout, mixed $retryAfter, ?string $problem): void
    {
        config()->set('queue.default', $default);
        config()->set('queue.connections.slow', ['driver' => 'redis', 'retry_after' => $retryAfter]);
        config()->set('queue.connections.fast', ['driver' => 'sqs']);
        config()->set('sso.metadata.claim_seconds', 3600);
        config()->set('sso.metadata.queue.connection', $connection);
        config()->set('sso.metadata.queue.timeout_seconds', $timeout);

        try {
            $read = (new MetadataSettings(config()))->timeoutSeconds();
        } catch (\InvalidArgumentException $exception) {
            $read = $exception->getMessage();
        }

        self::assertSame($problem ?? $timeout, $read);
    }

    /**
     * Rows of `[value, connection]`; `null` is the default connection.
     *
     * @return iterable<string, array{0: mixed, 1: ?string}>
     */
    public static function provideQueueConnections(): iterable
    {
        yield from [
            'none'              => [null, null],
            'empty'             => ['', null],
            'a configured name' => ['metadata', 'metadata'],
        ];
    }

    /**
     * The queue connection is `null` for the default, or a name
     * `queue.connections` configures.
     *
     * @param  mixed  $value
     * @param  ?string  $connection
     * @return void
     */
    #[DataProvider('provideQueueConnections')]
    public function testTheQueueConnectionIsTheDefaultOrAConfiguredOne(mixed $value, ?string $connection): void
    {
        config()->set('queue.connections.metadata', ['driver' => 'sync']);
        config()->set('sso.metadata.queue.connection', $value);

        self::assertSame($connection, (new MetadataSettings(config()))->queueConnection());
    }

    /**
     * Rows of `[key, value, message]`: refused queue settings and the problem
     * named.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedQueues(): iterable
    {
        yield from [
            'an unconfigured connection' => ['connection', 'nowhere', 'sso.metadata.queue.connection names [nowhere], which queue.connections does not configure.'],
            'a connection not a string'  => ['connection', 5, 'sso.metadata.queue.connection must be a name of at most 255 bytes, or null.'],
            'a name not a string'        => ['name', ['slow'], 'sso.metadata.queue.name must be a name of at most 255 bytes, or null.'],
            'a name too long'            => ['name', str_repeat('q', 256), 'sso.metadata.queue.name must be a name of at most 255 bytes, or null.'],
        ];
    }

    /**
     * A malformed or unconfigured queue connection or name fails closed naming
     * its key.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedQueues')]
    public function testAMalformedQueueFailsClosed(string $key, mixed $value, string $message): void
    {
        $settings = new MetadataSettings(config());

        config()->set('sso.metadata.queue.name', str_repeat('q', 255));

        self::assertSame(str_repeat('q', 255), $settings->queueName());

        config()->set('sso.metadata.queue.' . $key, $value);

        $this->expectExceptionObject(new \InvalidArgumentException($message));

        $key === 'connection' ? $settings->queueConnection() : $settings->queueName();
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
     * Rows of `[failures, wait]` under the defaults.
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
     * `[metadata]` checks the size cap with SAML on, and every setting with the
     * refresh on.
     *
     * @return void
     */
    public function testTheCheckAppliesWithTheFeatureAndChecksEachSetting(): void
    {
        $check = new MetadataCheck(config());

        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', false);
        config()->set('sso.features.metadata_refresh', true);
        self::assertFalse($check->applies());

        config()->set('sso.features.metadata_refresh', 'maybe');
        self::assertFalse($check->applies());

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', false);
        self::assertTrue($check->applies());
        self::assertSame([1048576, 86400, 300, 21600, 2592000, 300], array_map(static fn (\Closure $check): mixed => $check(), $check->checks()));

        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', true);
        self::assertTrue($check->applies());
        self::assertSame([1048576, 86400, 300, 21600, 2592000, 300], array_map(static fn (\Closure $check): mixed => $check(), $check->checks()));

        config()->set('sso.features.metadata_refresh', true);
        self::assertTrue($check->applies());
        self::assertSame([1048576, 86400, 300, 21600, 2592000, 300, null, null, 60, 1], array_map(static fn (\Closure $check): mixed => $check(), $check->checks()));
    }

    /**
     * A cap past its ceiling, or a timeout past the claim or the queue's
     * `retry_after`, fails the boot check.
     *
     * @return void
     */
    public function testTheBootCheckRefusesACapOrATimeoutOutOfBounds(): void
    {
        config()->set('sso.features.saml2', true);
        config()->set('sso.metadata.max_bytes', 268435457);

        $problems = [];

        foreach ((new MetadataCheck(config()))->checks() as $check) {
            try {
                $check();
            } catch (\InvalidArgumentException $exception) {
                $problems[] = $exception->getMessage();
            }
        }

        self::assertSame(['sso.metadata.max_bytes must be an integer from 65536 to 268435456.'], $problems);

        config()->set('sso.features.metadata_refresh', true);
        config()->set('sso.metadata.max_bytes', 268435456);
        config()->set('sso.metadata.queue.timeout_seconds', 301);

        $problems = [];

        foreach ((new MetadataCheck(config()))->checks() as $check) {
            try {
                $check();
            } catch (\InvalidArgumentException $exception) {
                $problems[] = $exception->getMessage();
            }
        }

        self::assertSame([self::TIMEOUT_PAST_CLAIM], $problems);

        config()->set('queue.default', 'redis');
        config()->set('queue.connections.redis', ['driver' => 'redis', 'retry_after' => 90]);
        config()->set('sso.metadata.queue.timeout_seconds', 90);

        $problems = [];

        foreach ((new MetadataCheck(config()))->checks() as $check) {
            try {
                $check();
            } catch (\InvalidArgumentException $exception) {
                $problems[] = $exception->getMessage();
            }
        }

        self::assertSame([
            'sso.metadata.queue.timeout_seconds must be shorter than the retry_after of queue connection [redis], so a refresh still running is never reserved again.',
        ], $problems);
    }
}
