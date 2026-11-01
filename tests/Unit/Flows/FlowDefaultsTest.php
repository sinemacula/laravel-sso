<?php

declare(strict_types = 1);

namespace Tests\Unit\Flows;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Stages\DomainReservation;
use SineMacula\Laravel\Sso\Completion\Stages\Provisioning;
use SineMacula\Laravel\Sso\Completion\Stages\UnbuiltStage;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Flows\NoReauthenticationSessions;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Links\OneLinkPerConnection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Unit tests for the flows' fail-closed defaults: no session is found for
 * reauthentication, nothing is linked, an identity holds one link per
 * connection, and the two seams of the completion pass every result on
 * unchanged; and for the stable values of the links' enums.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoReauthenticationSessions::class)]
#[CoversClass(SessionStanding::class)]
#[CoversClass(NoLinks::class)]
#[CoversClass(OneLinkPerConnection::class)]
#[CoversClass(DomainReservation::class)]
#[CoversClass(Provisioning::class)]
#[CoversClass(UnbuiltStage::class)]
#[CoversClass(LinkState::class)]
#[CoversClass(LinkOrigin::class)]
final class FlowDefaultsTest extends TestCase
{
    /**
     * No identity is ever signed in on a session, so no `reauthenticate` flow
     * starts by default.
     *
     * @return void
     */
    public function testNoSessionIsFoundForReauthentication(): void
    {
        $standing = (new NoReauthenticationSessions)->standing(new IdentityReference('user', '1'), 'session-1', new ExampleConnection);

        self::assertSame(SessionStanding::NOT_SIGNED_IN, $standing);
        self::assertFalse($standing->isSignedIn());
        self::assertTrue(SessionStanding::SIGNED_IN->isSignedIn());
        self::assertSame(['signed_in', 'not_signed_in'], array_column(SessionStanding::cases(), 'value'));
    }

    /**
     * Nothing is linked, and an identity holds one link per connection.
     *
     * @return void
     */
    public function testNothingIsLinkedAndOneLinkIsAllowed(): void
    {
        self::assertNull((new NoLinks)->resolve(ExampleResults::full()));
        self::assertSame(1, (new OneLinkPerConnection)->maxLinks(new IdentityReference('user', '1'), new ExampleConnection));
        self::assertSame(1, OneLinkPerConnection::MAX_LINKS);
        self::assertSame(['active', 'reserved'], array_column(LinkState::cases(), 'value'));
        self::assertSame(['link_purpose', 'provisioning', 'verified_domain', 'migration'], array_column(LinkOrigin::cases(), 'value'));
    }

    /**
     * The domain reservation and provisioning seams pass the state on
     * unchanged.
     *
     * @return void
     */
    public function testTheSeamsPassEveryResultOn(): void
    {
        $state = CompletionState::arrived('01jbexampleconnection00000', new CompletionRequest('POST', '', []))->withResult(ExampleResults::full());

        foreach ([new DomainReservation, new Provisioning] as $stage) {

            $outcome = $stage->run($state);

            self::assertTrue($outcome->isProceeding());
            self::assertSame($state, $outcome->state);
            self::assertNull($outcome->reason);
        }
    }
}
