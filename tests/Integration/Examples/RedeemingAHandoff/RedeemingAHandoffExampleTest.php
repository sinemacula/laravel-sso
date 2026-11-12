<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/redeeming-a-handoff.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(RedemptionResult::class)]
final class RedeemingAHandoffExampleTest extends ExampleTestCase
{
    /** @var string The sign-in endpoint, under Laravel's API prefix. */
    private const string SIGN_IN = '/api/auth/sessions';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /** @var \Tests\Integration\Examples\RedeemingAHandoff\SignIns The application's sign-ins. */
    private SignIns $signIns;

    /**
     * Register the sign-in endpoint and make the OIDC connection and person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->signIns = new SignIns($this->clock);
        $this->instance(SignIns::class, $this->signIns);

        Route::post(self::SIGN_IN, [SsoHandoffController::class, 'signIn']);

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
        $this->person       = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * A `link` code is admitted only for the identity it is bound to, and a
     * mismatched caller spends it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkIsAdmittedForTheCallerAlone(): void
    {
        $someoneElse = new IdentityReference('App\Models\User', 'person-2');
        $refused     = $this->linkAsCaller($this->person, $someoneElse);

        self::assertTrue($refused['result']->isRefused());
        self::assertSame(FailureReason::IDENTITY_MISMATCH, $refused['result']->reason);
        self::assertSame(FailureReason::REPLAYED, self::linkAt($refused['input'], new Caller($this->person, 'session-1'))->reason);
        self::assertSame([], $this->linksOf($this->person));

        $linked = $this->linkAsCaller($this->person, $this->person)['result'];

        self::assertTrue($linked->isRedeemed());
        self::assertTrue($linked->isAdmitted());
        self::assertTrue($linked->identity?->is($this->person));
        self::assertNotNull($linked->linkId);
        self::assertSame([$linked->linkId], $this->linksOf($this->person));
        self::assertSame([], $this->linksOf($someoneElse));
    }

    /**
     * A linked person's `sign_in` code is answered with a token once, and
     * `replayed` after.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheSignInEndpointAnswersATokenForTheLinkedIdentity(): void
    {
        $link = $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);
        $body = $this->signInBody(Purpose::SIGN_IN);

        $token = self::sent($this->postJson(self::SIGN_IN, $body), 200)->json('token');

        self::assertIsString($token);

        $sessionId = $this->signIns->sessionOf($token);

        self::assertNotNull($sessionId);
        self::assertTrue($this->signIns->identityOf($sessionId)?->is($this->person));
        self::assertSame($link->linkId, $this->signIns->linkOf($sessionId));

        $replayed = $this->postJson(self::SIGN_IN, $body);

        self::sent($replayed, 400)->assertExactJson(['error' => FailureReason::REPLAYED->value]);
        self::assertSame([$sessionId], $this->signIns->sessionsOf($this->person));
    }

    /**
     * The sign-in endpoint refuses a `link` code and an unlinked handoff with a
     * `400`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheSignInEndpointRefusesAnotherPurposeAndAnUnlinkedHandoff(): void
    {
        $mismatched = $this->postJson(self::SIGN_IN, $this->signInBody(Purpose::LINK, $this->person));

        self::sent($mismatched, 400)->assertExactJson(['error' => FailureReason::PURPOSE_MISMATCH->value]);

        // This endpoint resolves no identity, so it signs nobody in
        config()->set('sso.applications.' . self::APPLICATION . '.unlinked_handoffs', true);

        $unlinked = $this->postJson(self::SIGN_IN, $this->signInBody(Purpose::SIGN_IN));

        self::sent($unlinked, 400)->assertExactJson(['error' => FailureReason::UNLINKED->value]);
        self::assertSame([], $this->signIns->sessionsOf($this->person));
    }

    /**
     * A full redemption limit is a `429` with its `Retry-After`.
     *
     * @return void
     */
    public function testAFullRedemptionLimitIsA429WithItsWait(): void
    {
        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $body = ['application' => self::APPLICATION, 'connection' => $this->connectionId, 'code' => 'not-a-code', 'verifier' => 'not-a-verifier'];

        self::sent($this->postJson(self::SIGN_IN, $body), 400)->assertExactJson(['error' => FailureReason::HANDOFF_UNKNOWN->value]);

        $limited = $this->postJson(self::SIGN_IN, $body);

        self::sent($limited, 429)->assertExactJson(['error' => 'rate_limited'])->assertHeader('Retry-After', '60');
    }

    /**
     * Complete a `link` flow for the identity and admit its code as the caller.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return array{input: array{connection: string, code: string, verifier: string}, result: \SineMacula\Laravel\Sso\Handoffs\RedemptionResult}
     *
     * @throws \Random\RandomException
     */
    private function linkAsCaller(IdentityReference $identity, IdentityReference $caller): array
    {
        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $identity);
        $input = ['connection' => $this->connectionId, 'code' => $this->codeFor($start), 'verifier' => self::verifierOf($start)];

        return ['input' => $input, 'result' => self::linkAt($input, new Caller($caller, 'session-1'))];
    }

    /**
     * The body a client posts to the sign-in endpoint for a completed flow.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return array{application: string, connection: string, code: string, verifier: string}
     *
     * @throws \Random\RandomException
     */
    private function signInBody(Purpose $purpose, ?IdentityReference $identity = null): array
    {
        $start = $this->startFlow($purpose, $this->connectionId, $identity);

        return ['application' => self::APPLICATION, 'connection' => $this->connectionId, 'code' => $this->codeFor($start), 'verifier' => self::verifierOf($start)];
    }

    /**
     * The code the provider's answer to the started flow is redirected with.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function codeFor(StartResult $start): string
    {
        return $this->respondAtProvider($this->provider, $this->connectionId, $start)->code();
    }

    /**
     * The ids of the identity's links, oldest first.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return list<string>
     */
    private function linksOf(IdentityReference $identity): array
    {
        return array_map(static fn (LinkSummary $link): string => $link->id, app(LinkService::class)->list($identity));
    }

    /**
     * Run the application's `link` endpoint for the input and caller.
     *
     * @param  array{connection: string, code: string, verifier: string}  $input
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private static function linkAt(array $input, Caller $caller): RedemptionResult
    {
        return require __DIR__ . '/redemptions/link.php';
    }

    /**
     * Assert the status and `Cache-Control: no-store`, which Symfony writes as
     * `no-store, private`.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  int  $status
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private static function sent(TestResponse $response, int $status): TestResponse
    {
        return $response->assertStatus($status)->assertHeader('Cache-Control', 'no-store, private');
    }
}
