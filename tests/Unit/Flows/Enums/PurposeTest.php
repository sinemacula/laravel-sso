<?php

declare(strict_types = 1);

namespace Tests\Unit\Flows\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

/**
 * Unit tests for the purposes a flow is started for: the three SSO-5.1 names,
 * stable, and which forces fresh authentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Purpose::class)]
final class PurposeTest extends TestCase
{
    /**
     * The purposes are the three SSO-5.1 names, in this order.
     *
     * @return void
     */
    public function testThePurposesAreStable(): void
    {
        self::assertSame(['sign_in', 'link', 'reauthenticate'], array_column(Purpose::cases(), 'value'));
    }

    /**
     * Only `reauthenticate` forces fresh authentication at the identity
     * provider.
     *
     * @return void
     */
    public function testOnlyReauthenticationForcesAuthentication(): void
    {
        self::assertTrue(Purpose::REAUTHENTICATE->forcesAuthentication());
        self::assertFalse(Purpose::SIGN_IN->forcesAuthentication());
        self::assertFalse(Purpose::LINK->forcesAuthentication());
    }
}
