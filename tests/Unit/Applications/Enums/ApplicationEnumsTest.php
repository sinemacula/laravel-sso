<?php

declare(strict_types = 1);

namespace Tests\Unit\Applications\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;
use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;

/**
 * Unit tests for the application enums' stable values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffDelivery::class)]
#[CoversClass(ExternalSignIn::class)]
final class ApplicationEnumsTest extends TestCase
{
    /**
     * The deliveries are the fragment and the query, in that order.
     *
     * @return void
     */
    public function testTheDeliveriesAreStable(): void
    {
        self::assertSame(['fragment', 'query'], array_column(HandoffDelivery::cases(), 'value'));
    }

    /**
     * Only `allowed` allows external sign-in.
     *
     * @return void
     */
    public function testOnlyAllowedAllows(): void
    {
        self::assertSame(['allowed', 'not_allowed'], array_column(ExternalSignIn::cases(), 'value'));
        self::assertTrue(ExternalSignIn::ALLOWED->isAllowed());
        self::assertFalse(ExternalSignIn::NOT_ALLOWED->isAllowed());
    }
}
