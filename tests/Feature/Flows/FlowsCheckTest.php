<?php

declare(strict_types = 1);

namespace Tests\Feature\Flows;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Flows\FlowsCheck;
use SineMacula\Laravel\Sso\Flows\FlowSettings;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for the flows' settings and `[flows]`: the authorisation
 * request's lifetime and the least time a discovery start takes, each with its
 * default and its range, checked while the package is in use.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FlowSettings::class)]
#[CoversClass(FlowsCheck::class)]
final class FlowsCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * The defaults: ten minutes, and a quarter of a second.
     *
     * @return void
     */
    public function testTheDefaults(): void
    {
        $settings = app(FlowSettings::class);

        self::assertSame(600, $settings->requestTtlSeconds());
        self::assertSame(250, $settings->discoveryMinimumDurationMilliseconds());

        config()->set('sso.authorization_requests', []);
        config()->set('sso.discovery', []);

        self::assertSame(600, $settings->requestTtlSeconds());
        self::assertSame(250, $settings->discoveryMinimumDurationMilliseconds());
    }

    /**
     * A request lives 60 to 900 seconds; discovery takes at least 50 to 2000
     * milliseconds.
     *
     * @return void
     */
    public function testTheRanges(): void
    {
        $settings = app(FlowSettings::class);

        foreach ([60, 900, '61'] as $ttl) {
            config()->set('sso.authorization_requests.ttl_seconds', $ttl);
            self::assertSame((int) $ttl, $settings->requestTtlSeconds());
        }

        foreach ([50, 2000] as $duration) {
            config()->set('sso.discovery.minimum_duration_milliseconds', $duration);
            self::assertSame($duration, $settings->discoveryMinimumDurationMilliseconds());
        }

        $this->useThePackage();

        config()->set('sso.authorization_requests.ttl_seconds', 59);
        config()->set('sso.discovery.minimum_duration_milliseconds', 2001);

        self::assertSame([
            'sso.authorization_requests.ttl_seconds must be an integer from 60 to 900.',
            'sso.discovery.minimum_duration_milliseconds must be an integer from 50 to 2000.',
        ], $this->problemsOf(FlowsCheck::class));

        config()->set('sso.authorization_requests.ttl_seconds', 901);
        config()->set('sso.discovery.minimum_duration_milliseconds', 49);

        self::assertSame([
            'sso.authorization_requests.ttl_seconds must be an integer from 60 to 900.',
            'sso.discovery.minimum_duration_milliseconds must be an integer from 50 to 2000.',
        ], $this->problemsOf(FlowsCheck::class));
    }

    /**
     * Not checked while the package is not in use, however malformed; checked
     * and passing with the defaults once it is.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        config()->set('sso.authorization_requests.ttl_seconds', 'soon');

        self::assertNull($this->problemsOf(FlowsCheck::class));

        $this->useThePackage();
        config()->set('sso.authorization_requests.ttl_seconds', 600);

        self::assertSame([], $this->problemsOf(FlowsCheck::class));
        self::assertSame(600, FlowSettings::DEFAULT_REQUEST_TTL_SECONDS);
        self::assertSame(60, FlowSettings::MIN_REQUEST_TTL_SECONDS);
        self::assertSame(900, FlowSettings::MAX_REQUEST_TTL_SECONDS);
        self::assertSame(250, FlowSettings::DEFAULT_DISCOVERY_DURATION_MILLISECONDS);
        self::assertSame(50, FlowSettings::MIN_DISCOVERY_DURATION_MILLISECONDS);
        self::assertSame(2000, FlowSettings::MAX_DISCOVERY_DURATION_MILLISECONDS);
    }
}
