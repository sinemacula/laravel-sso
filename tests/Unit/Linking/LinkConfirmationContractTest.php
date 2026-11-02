<?php

declare(strict_types = 1);

namespace Tests\Unit\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Unit tests for the link confirmation contract's default and its verdict: the
 * default never counts a caller's authentication as independent.
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
     * The default answers `dependent` for anyone, through any connection.
     *
     * @return void
     */
    public function testTheDefaultAnswersDependent(): void
    {
        $contract = new RefusingLinkConfirmation;

        $person = new IdentityReference('App\Models\User', '7');
        $admin  = new IdentityReference('App\Models\Admin', 'root');

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $contract->judge($person, new ExampleConnection, ['link-1']));
        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $contract->judge($admin, new ExampleConnection('oidc'), ['link-1', 'link-2']));
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
