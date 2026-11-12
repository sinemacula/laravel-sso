<?php

declare(strict_types = 1);

namespace Tests\Unit\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Linking\RefusingLinkConfirmation;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Unit tests for the default link confirmation contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefusingLinkConfirmation::class)]
final class RefusingLinkConfirmationTest extends TestCase
{
    /**
     * The default answers `dependent` for any caller through any connection.
     *
     * @return void
     */
    public function testTheDefaultAnswersDependent(): void
    {
        $contract = new RefusingLinkConfirmation;

        $person = new Caller(new IdentityReference('App\Models\User', '7'), 'session-1');
        $admin  = new Caller(new IdentityReference('App\Models\Admin', 'root'));

        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $contract->judge($person, new ExampleConnection, ['link-1']));
        self::assertSame(LinkConfirmationVerdict::DEPENDENT, $contract->judge($admin, new ExampleConnection('oidc'), ['link-1', 'link-2']));
    }
}
