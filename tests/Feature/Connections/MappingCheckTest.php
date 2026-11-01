<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\MappingCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[mapping]`: checked only while the package is in use, each
 * cap read as `MappingLimits` reads it, and every malformed cap reported by its
 * key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MappingCheck::class)]
final class MappingCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * Not checked while the package is not in use, however malformed.
     *
     * @return void
     */
    public function testDoesNotApplyWhileThePackageIsNotInUse(): void
    {
        config()->set('sso.mapping.max_values', 0);

        self::assertNull($this->problemsOf(MappingCheck::class));
    }

    /**
     * The shipped caps pass once the package is in use.
     *
     * @return void
     */
    public function testTheShippedCapsPass(): void
    {
        $this->useThePackage();

        self::assertSame([], $this->problemsOf(MappingCheck::class));
    }

    /**
     * A malformed protocol switch counts as the package in use, so the caps are
     * checked rather than skipped.
     *
     * @return void
     */
    public function testAppliesOverAMalformedProtocolSwitch(): void
    {
        config()->set('sso.features.oidc', 'perhaps');
        config()->set('sso.mapping.max_custom_attributes', 101);

        self::assertSame(['sso.mapping.max_custom_attributes must be an integer from 0 to 100.'], $this->problemsOf(MappingCheck::class));
    }

    /**
     * Each malformed cap is reported by its key, in order.
     *
     * @return void
     */
    public function testReportsEachMalformedCap(): void
    {
        $this->useThePackage();

        config()->set('sso.mapping', ['max_value_length' => 32, 'max_values' => 'many', 'max_custom_attributes' => -1]);

        self::assertSame([
            'sso.mapping.max_value_length must be an integer from 64 to 65535.',
            'sso.mapping.max_values must be an integer from 1 to 10000.',
            'sso.mapping.max_custom_attributes must be an integer from 0 to 100.',
        ], $this->problemsOf(MappingCheck::class));
    }

    /**
     * The digit strings `env()` gives pass.
     *
     * @return void
     */
    public function testAcceptsDigitStrings(): void
    {
        $this->useThePackage();

        config()->set('sso.mapping', ['max_value_length' => '2048', 'max_values' => '50', 'max_custom_attributes' => '5']);

        self::assertSame([], $this->problemsOf(MappingCheck::class));
    }
}
