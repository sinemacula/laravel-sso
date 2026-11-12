<?php

declare(strict_types = 1);

namespace Tests\Unit\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use Tests\TestCase;

/**
 * Unit tests for the link confirmation contract's binding and verdict.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefusingLinkConfirmation::class)]
#[CoversClass(LinkConfirmationVerdict::class)]
final class LinkConfirmationContractTest extends TestCase
{
    /**
     * The package binds the default that refuses.
     *
     * @return void
     */
    public function testTheDefaultBindingRefuses(): void
    {
        self::assertInstanceOf(RefusingLinkConfirmation::class, app(LinkConfirmation::class));
    }

    /**
     * The values are stable, and only `independent` counts.
     *
     * @return void
     */
    public function testTheVerdicts(): void
    {
        self::assertSame(['independent', 'dependent'], array_column(LinkConfirmationVerdict::cases(), 'value'));
        self::assertTrue(LinkConfirmationVerdict::INDEPENDENT->isIndependent());
        self::assertFalse(LinkConfirmationVerdict::DEPENDENT->isIndependent());
    }
}
