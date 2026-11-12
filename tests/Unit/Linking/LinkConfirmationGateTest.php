<?php

declare(strict_types = 1);

namespace Tests\Unit\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Linking\LinkConfirmationGate;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Fixtures\Linking\ScriptedLinkConfirmation;
use Tests\TestCase;

/**
 * Unit tests for the link confirmation gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkConfirmationGate::class)]
final class LinkConfirmationGateTest extends TestCase
{
    /**
     * An identity that never held a domain link passes unasked.
     *
     * @return void
     */
    public function testAnIdentityThatNeverHeldADomainLinkIsNotAsked(): void
    {
        $confirmation = new ScriptedLinkConfirmation(LinkConfirmationVerdict::DEPENDENT);

        self::assertTrue((new LinkConfirmationGate($confirmation))->allows(self::caller(), self::connection(), [], false));
        self::assertSame([], $confirmation->asked);
    }

    /**
     * An identity that holds or held a domain link needs `independent`.
     *
     * @return void
     */
    public function testAnIdentityThatHoldsOrHeldADomainLinkIsJudgedAsTheCaller(): void
    {
        $caller       = self::caller();
        $confirmation = new ScriptedLinkConfirmation;
        $gate         = new LinkConfirmationGate($confirmation);

        self::assertTrue($gate->allows($caller, self::connection(), ['link-1'], false));
        self::assertTrue($gate->allows($caller, self::connection(), [], true));

        $confirmation->verdict = LinkConfirmationVerdict::DEPENDENT;

        self::assertFalse($gate->allows($caller, self::connection(), ['link-1'], true));
        self::assertFalse($gate->allows($caller, self::connection(), [], true));

        self::assertSame([$caller, $caller, $caller, $caller], $confirmation->callers);
        self::assertSame('session-1', $confirmation->callers[0]->sessionId);
        self::assertSame([
            ['42', 'connection-1', ['link-1']],
            ['42', 'connection-1', []],
            ['42', 'connection-1', ['link-1']],
            ['42', 'connection-1', []],
        ], $confirmation->asked);
    }

    /**
     * The caller a redemption is made for, on its session.
     *
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    private static function caller(): Caller
    {
        return new Caller(new IdentityReference('App\Models\User', '42'), 'session-1');
    }

    /**
     * A connection, as locked.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private static function connection(): Connection
    {
        return (new Connection)->forceFill(['id' => 'connection-1']);
    }
}
