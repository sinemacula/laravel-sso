<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use SineMacula\Laravel\Sso\Testing\Saml\FakeAuthnRequest;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;

/**
 * The testing guide's SAML examples: each purpose from start to redemption, and
 * why a response is made at the package's clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeSamlIdentityProvider::class)]
#[CoversClass(FakeAuthnRequest::class)]
#[CoversClass(HandoffRedirect::class)]
final class SamlExampleTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The identity provider. */
    private FakeSamlIdentityProvider $idp;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Make the provider and a connection that trusts it, and the person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->idp          = new FakeSamlIdentityProvider;
        $this->connectionId = $this->makeSamlConnection($this->idp);
        $this->person       = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * A `link` code links the subject to the person once; the same code again
     * is a replay.
     *
     * @return void
     */
    public function testLinkingASubjectToAnIdentity(): void
    {
        $client = Clients::browser();
        // @snippet-start saml-link
        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);

        // The provider reads the AuthnRequest the start sent, and answers it
        $request  = $this->idp->receive($start);
        $response = $this->idp->respondTo($request, $this->clock->now());

        self::assertSame(FakeSamlIdentityProvider::SSO_URL, $request->destination);

        // The browser posts the response, with the RelayState, to the assertion
        // consumer service
        $result = app(CompletionService::class)->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $this->connectionId,
            $response->completionRequest($request->relayState),
            $client,
        );
        $redirect = HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'POST'));

        // The client redeems only a code whose reference is the one it started
        self::assertSame($start->reference?->value, $redirect->reference);

        $linked = $this->redeemLink($this->connectionId, $redirect, $start, $this->person);

        self::assertTrue($linked->isRedeemed());
        self::assertNotNull($linked->linkId);
        self::assertEquals($this->person, $linked->identity);
        // @snippet-end saml-link
        // @snippet-start saml-link-replayed
        $replayed = $this->redeemLink($this->connectionId, $redirect, $start, $this->person);

        self::assertTrue($replayed->isRefused());
        self::assertSame(FailureReason::REPLAYED, $replayed->reason);
        // @snippet-end saml-link-replayed
    }

    /**
     * A `sign_in` admits the linked person; an untrusted signature fails the
     * flow.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSigningIn(): void
    {
        $this->linkThroughFlow($this->idp, $this->connectionId, $this->person);

        // @snippet-start saml-sign-in
        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);
        $signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

        self::assertTrue($signedIn->isAdmitted());
        self::assertEquals($this->person, $signedIn->linkedIdentity);
        // The provider authenticated the person a minute before it answered
        self::assertSame('2026-11-01T09:29:00Z', $this->sessions->authenticatedAt('session-1')?->toIso8601ZuluString());
        // @snippet-end saml-sign-in
        // @snippet-start saml-sign-in-refused
        $attacker = new FakeSamlIdentityProvider($this->idp->entityId);
        $forged   = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->signedBy($attacker->signer());
        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start, $forged);

        self::assertFalse($redirect->hasCode());
        self::assertSame(FailureReason::SIGNATURE_INVALID->value, $redirect->error);
        // @snippet-end saml-sign-in-refused
    }

    /**
     * A `reauthenticate` renews the session to the provider's time; one for
     * another session never starts.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReauthenticating(): void
    {
        $this->linkThroughFlow($this->idp, $this->connectionId, $this->person);
        $this->signInThroughFlow($this->idp, $this->connectionId, 'session-1');

        // @snippet-start saml-reauthenticate
        $this->clock->advance(3600);

        $start   = $this->startFlow(Purpose::REAUTHENTICATE, $this->connectionId, $this->person, 'session-1');
        $request = $this->idp->receive($start);

        self::assertTrue($request->forceAuthn);

        $redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);
        $renewed  = $this->admitReauthentication($this->connectionId, $redirect, $start);

        self::assertTrue($renewed->isAdmitted());
        self::assertSame('session-1', $renewed->sessionId);
        self::assertSame('2026-11-01T10:30:00Z', $this->sessions->authenticatedAt('session-1')?->toIso8601ZuluString());
        // @snippet-end saml-reauthenticate
        // @snippet-start saml-reauthenticate-refused
        $refused = $this->startFlow(Purpose::REAUTHENTICATE, $this->connectionId, $this->person, 'session-2');

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::SESSION_INELIGIBLE, $refused->reason);
        // @snippet-end saml-reauthenticate-refused
    }

    /**
     * A response made at Laravel's time after time travel is refused as
     * expired; one made at the package's clock is accepted.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResponseIsMadeAtTheInstantOfThePackagesClock(): void
    {
        $client = Clients::browser();
        // @snippet-start saml-instant
        $this->travelTo(CarbonImmutable::parse('2026-11-02T09:30:00Z'));

        $start   = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $request = $this->idp->receive($start);

        // Made at Laravel's time, a day after the package's clock
        $response = $this->idp->respondTo($request);
        $result   = app(CompletionService::class)->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $this->connectionId,
            $response->completionRequest($request->relayState),
            $client,
        );

        self::assertSame(FailureReason::ASSERTION_EXPIRED, $result->reason);

        // Made at the package's clock's instant
        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);

        self::assertTrue($redirect->hasCode());
        // @snippet-end saml-instant
        $this->travelBack();
    }
}
