<?php

declare(strict_types = 1);

namespace Tests\Unit\Flows;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Fixtures\Protocols\ExampleConnection;

/**
 * The package keeps no sessions (SSO-5.10): the default contract answers
 * `not_signed_in` to every question, so no `reauthenticate` flow starts and no
 * code is redeemed, and being asked to renew a session is the package's own
 * mistake. Only `signed_in` counts as signed in, and the values are stable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoReauthenticationSessions::class)]
#[CoversClass(SessionStanding::class)]
final class ReauthenticationSessionsDefaultTest extends TestCase
{
    /**
     * Rows of `[identity, session]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: string}>
     */
    public static function provideQuestions(): iterable
    {
        yield 'a session' => [new IdentityReference('App\Models\User', '7'), 'session-1'];
        yield 'another identity on another session' => [new IdentityReference('App\Models\Admin', '8'), 'session-2'];
    }

    /**
     * Nobody is signed in when a flow starts.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $session
     * @return void
     */
    #[DataProvider('provideQuestions')]
    public function testNobodyIsSignedInWhenAFlowStarts(IdentityReference $identity, string $session): void
    {
        self::assertSame(SessionStanding::NOT_SIGNED_IN, (new NoReauthenticationSessions)->standing($identity, $session, new ExampleConnection));
    }

    /**
     * Nobody is signed in through any link at redemption.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $session
     * @return void
     */
    #[DataProvider('provideQuestions')]
    public function testNobodyIsSignedInAtRedemption(IdentityReference $identity, string $session): void
    {
        self::assertSame(SessionStanding::NOT_SIGNED_IN, (new NoReauthenticationSessions)->lockedStanding($identity, $session, 'web', new ExampleConnection, 'link-1'));
    }

    /**
     * Being asked to renew is the package's own mistake, with or without
     * evidence, since no session is ever found.
     *
     * @return void
     */
    public function testARenewalIsTheCallersMistake(): void
    {
        $at = CarbonImmutable::parse('2026-11-01T09:30:00Z');

        foreach ([null, new AcceptedEvidence('connection', $at)] as $evidence) {

            try {
                (new NoReauthenticationSessions)->renewAuthentication(new IdentityReference('App\Models\User', '7'), 'session-1', $at, $evidence);
                self::fail('The default contract renewed a session.');
            } catch (\LogicException $exception) {
                self::assertSame('The default reauthentication sessions hold no session to renew.', $exception->getMessage());
            }
        }
    }

    /**
     * The default implements the contract, and holds nothing between calls.
     *
     * @return void
     */
    public function testTheDefaultHoldsNothing(): void
    {
        $default = new NoReauthenticationSessions;

        self::assertInstanceOf(ReauthenticationSessions::class, $default);
        self::assertSame([], (new \ReflectionClass($default))->getProperties());
    }

    /**
     * Only `signed_in` counts as signed in, and the values are stable.
     *
     * @return void
     */
    public function testOnlySignedInIsSignedIn(): void
    {
        self::assertSame(['signed_in', 'not_signed_in'], array_column(SessionStanding::cases(), 'value'));
        self::assertTrue(SessionStanding::SIGNED_IN->isSignedIn());
        self::assertFalse(SessionStanding::NOT_SIGNED_IN->isSignedIn());
    }
}
