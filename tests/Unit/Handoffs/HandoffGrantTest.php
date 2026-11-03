<?php

declare(strict_types = 1);

namespace Tests\Unit\Handoffs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Unit tests for what a handoff code is issued for and what an issuer answers:
 * every part of the grant kept, its identity and session fitting its purpose,
 * its ids bounded; the issued code never shown or serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffGrant::class)]
#[CoversClass(IssuedHandoff::class)]
final class HandoffGrantTest extends TestCase
{
    /**
     * Every part of a grant is kept.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testKeepsEveryPart(): void
    {
        $result    = ExampleResults::full(Purpose::REAUTHENTICATE);
        $challenge = Verifier::generate()->challenge();
        $expires   = CarbonImmutable::parse('2026-11-01T10:01:00Z');
        $linked    = new IdentityReference('user', '1');
        $identity  = new IdentityReference('user', '2');
        $notAfter  = CarbonImmutable::parse('2026-11-01T18:00:00Z');
        $grant     = new HandoffGrant($result, $challenge, $expires, 7, $linked, $identity, 'session-1', $notAfter);

        self::assertSame($result, $grant->result);
        self::assertSame($challenge, $grant->challenge);
        self::assertSame($expires, $grant->expiresAt);
        self::assertSame(7, $grant->trustVersion);
        self::assertSame($linked, $grant->linkedIdentity);
        self::assertSame($identity, $grant->identity);
        self::assertSame('session-1', $grant->sessionId);
        self::assertSame($notAfter, $grant->sessionNotAfter);
        self::assertSame(255, HandoffGrant::MAX_ID_LENGTH);

        $bare = new HandoffGrant(ExampleResults::bare(), $challenge, $expires, 0);

        self::assertNull($bare->linkedIdentity);
        self::assertNull($bare->identity);
        self::assertNull($bare->sessionId);
        self::assertNull($bare->sessionNotAfter);
    }

    /**
     * Rows of `[purpose, identity, session, message]`: bindings that do not fit
     * their purpose.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: bool, 2: ?string, 3: string}>
     */
    public static function provideMisfitBindings(): iterable
    {
        yield 'a sign-in with an identity' => [Purpose::SIGN_IN, true, null, 'A [sign_in] handoff grant names no identity and no session.'];
        yield 'a sign-in with a session' => [Purpose::SIGN_IN, false, 'session-1', 'A [sign_in] handoff grant names no identity and no session.'];
        yield 'a link without its identity' => [Purpose::LINK, false, null, 'A [link] handoff grant names the identity and no session.'];
        yield 'a link with a session' => [Purpose::LINK, true, 'session-1', 'A [link] handoff grant names the identity and no session.'];
        yield 'a reauthentication without its identity' => [Purpose::REAUTHENTICATE, false, 'session-1', 'A [reauthenticate] handoff grant names the identity and the session.'];
        yield 'a reauthentication without its session' => [Purpose::REAUTHENTICATE, true, null, 'A [reauthenticate] handoff grant names the identity and the session.'];
    }

    /**
     * An identity or a session that does not fit the purpose is refused.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  bool  $identity
     * @param  ?string  $session
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMisfitBindings')]
    public function testRefusesABindingThatDoesNotFitItsPurpose(Purpose $purpose, bool $identity, ?string $session, string $message): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException($message));

        $challenge = S256Challenge::fromString(str_repeat('c', 43));
        $named     = $identity ? new IdentityReference('user', '1') : null;

        new HandoffGrant(ExampleResults::full($purpose), $challenge, CarbonImmutable::now(), 0, identity: $named, sessionId: $session);
    }

    /**
     * Each purpose's own binding is accepted.
     *
     * @return void
     */
    public function testAcceptsEachPurposesBinding(): void
    {
        $challenge = S256Challenge::fromString(str_repeat('c', 43));
        $identity  = new IdentityReference('user', '1');
        $now       = CarbonImmutable::now();
        $again     = new HandoffGrant(ExampleResults::full(Purpose::REAUTHENTICATE), $challenge, $now, 0, identity: $identity, sessionId: 's');

        self::assertNull((new HandoffGrant(ExampleResults::full(Purpose::SIGN_IN), $challenge, $now, 0))->identity);
        self::assertSame($identity, (new HandoffGrant(ExampleResults::full(Purpose::LINK), $challenge, $now, 0, identity: $identity))->identity);
        self::assertSame('s', $again->sessionId);
    }

    /**
     * A session id or link id is 1 to 255 bytes.
     *
     * @return void
     */
    public function testBoundsItsIds(): void
    {
        $challenge = S256Challenge::fromString(str_repeat('c', 43));
        $identity  = new IdentityReference('user', '1');
        $now       = CarbonImmutable::now();
        $again     = ExampleResults::full(Purpose::REAUTHENTICATE);

        self::assertSame(str_repeat('v', 255), (new HandoffGrant(ExampleResults::bare(), $challenge, $now, 0, linkId: str_repeat('v', 255)))->linkId);

        $messages = [];
        $grants   = [
            static fn (): HandoffGrant => new HandoffGrant(ExampleResults::bare(), $challenge, $now, 0, linkId: str_repeat('v', 256)),
            static fn (): HandoffGrant => new HandoffGrant(ExampleResults::bare(), $challenge, $now, 0, linkId: ''),
            static fn (): HandoffGrant => new HandoffGrant($again, $challenge, $now, 0, identity: $identity, sessionId: str_repeat('s', 256)),
            static fn (): HandoffGrant => new HandoffGrant($again, $challenge, $now, 0, identity: $identity, sessionId: ''),
        ];

        foreach ($grants as $grant) {
            try {
                $grant();
                $messages[] = 'accepted';
            } catch (\InvalidArgumentException $exception) {
                $messages[] = $exception->getMessage();
            }
        }

        self::assertSame([
            'A handoff grant\'s link id is 1 to 255 bytes.',
            'A handoff grant\'s link id is 1 to 255 bytes.',
            'A handoff grant\'s session id is 1 to 255 bytes.',
            'A handoff grant\'s session id is 1 to 255 bytes.',
        ], $messages);
    }

    /**
     * A reservation binds a `sign_in` grant that resolved to no identity, and
     * is kept.
     *
     * @return void
     */
    public function testAReservationBindsAnUnlinkedSignIn(): void
    {
        $challenge = S256Challenge::fromString(str_repeat('c', 43));
        $grant     = new HandoffGrant(ExampleResults::full(Purpose::SIGN_IN), $challenge, CarbonImmutable::now(), 0, reservationId: 'reservation-1');

        self::assertSame('reservation-1', $grant->reservationId);
        self::assertNull($grant->linkedIdentity);
    }

    /**
     * Rows of `[purpose, the identity it resolved to, the identity it names,
     * the session it names]`: what a reservation has no place on.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: bool, 2: bool, 3: ?string}>
     */
    public static function provideGrantsNoReservationFits(): iterable
    {
        yield 'a sign-in that resolved to an identity' => [Purpose::SIGN_IN, true, false, null];
        yield 'a link' => [Purpose::LINK, false, true, null];
        yield 'a link that resolved to an identity' => [Purpose::LINK, true, true, null];
        yield 'a reauthentication' => [Purpose::REAUTHENTICATE, false, true, 'session-1'];
    }

    /**
     * Anything else bound to a reservation is refused.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  bool  $linked
     * @param  bool  $named
     * @param  ?string  $session
     * @return void
     */
    #[DataProvider('provideGrantsNoReservationFits')]
    public function testAReservationFitsNothingElse(Purpose $purpose, bool $linked, bool $named, ?string $session): void
    {
        $identity = new IdentityReference('user', '1');

        $this->expectExceptionObject(new \InvalidArgumentException('A reservation belongs only to a [sign_in] handoff grant that resolved to no identity.'));

        new HandoffGrant(
            ExampleResults::full($purpose),
            S256Challenge::fromString(str_repeat('c', 43)),
            CarbonImmutable::now(),
            0,
            $linked ? $identity : null,
            $named ? $identity : null,
            $session,
            reservationId: 'reservation-1',
        );
    }

    /**
     * An issued handoff keeps its code and expiry, and never shows or
     * serialises the code.
     *
     * @return void
     */
    public function testAnIssuedHandoffKeepsItsCodeSecret(): void
    {
        $code    = HandoffCode::fromString(str_repeat('h', 43));
        $expires = CarbonImmutable::parse('2026-11-01T10:01:00Z');
        $issued  = new IssuedHandoff($code, $expires);

        self::assertSame($code, $issued->code);
        self::assertSame($expires, $issued->expiresAt);
        self::assertSame(['code' => '[redacted]', 'expires_at' => '2026-11-01T10:01:00Z'], $issued->__debugInfo());
        self::assertStringNotContainsString(str_repeat('h', 43), print_r($issued, true));

        $this->expectExceptionObject(new \LogicException('An issued handoff cannot be serialised.'));

        serialize($issued);
    }

    /**
     * An issued handoff cannot be unserialised.
     *
     * @return void
     */
    public function testAnIssuedHandoffCannotBeUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('An issued handoff cannot be unserialised.'));

        unserialize('O:45:"SineMacula\Laravel\Sso\Handoffs\IssuedHandoff":0:{}');
    }
}
