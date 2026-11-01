<?php

declare(strict_types = 1);

namespace Tests\Feature\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use Tests\TestCase;

/**
 * Feature tests for the feature switches: every feature off by default, read on
 * each call, a malformed switch failing closed for a flow and counting as on
 * for the checks, and the package in use only while a protocol is on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Features::class)]
final class FeaturesTest extends TestCase
{
    /**
     * With the published defaults, every feature is off and the package is not
     * in use.
     *
     * @return void
     */
    public function testEveryFeatureIsOffByDefault(): void
    {
        foreach (Feature::cases() as $feature) {
            self::assertFalse(Features::enabled($feature), $feature->value);
            self::assertFalse(Features::requested($feature), $feature->value);
        }

        self::assertFalse(Features::isInUse());
    }

    /**
     * A switch turned on is read at once, in each form a switch may take.
     *
     * @return void
     */
    public function testASwitchIsReadOnEachCall(): void
    {
        foreach ([true, 1, '1', 'true'] as $on) {

            config()->set('sso.features.discovery', $on);

            self::assertTrue(Features::enabled(Feature::DISCOVERY));
            self::assertTrue(Features::requested(Feature::DISCOVERY));
        }

        config()->set('sso.features.discovery', '0');

        self::assertFalse(Features::enabled(Feature::DISCOVERY));
        self::assertFalse(Features::requested(Feature::DISCOVERY));
    }

    /**
     * A malformed switch fails closed for a flow, naming its key, and counts as
     * on for the checks.
     *
     * @return void
     */
    public function testAMalformedSwitchFailsClosed(): void
    {
        config()->set('sso.features.enforcement', 'yes');

        self::assertTrue(Features::requested(Feature::ENFORCEMENT));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('sso.features.enforcement must be true or false.');

        Features::enabled(Feature::ENFORCEMENT);
    }

    /**
     * The package is in use while either protocol is on, or its switch is
     * malformed; no other feature puts it in use.
     *
     * @return void
     */
    public function testThePackageIsInUseWhileAProtocolIsOn(): void
    {
        foreach (Feature::cases() as $feature) {

            if ($feature->isProtocol()) {
                continue;
            }

            config()->set($feature->key(), true);
        }

        self::assertFalse(Features::isInUse());

        config()->set('sso.features.oidc', true);

        self::assertTrue(Features::isInUse());

        config()->set('sso.features.oidc', false);
        config()->set('sso.features.saml2', 'on');

        self::assertTrue(Features::isInUse());
    }

    /**
     * `Features` is a utility container, not to be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(Features::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(Features::class, $instance);
    }
}
