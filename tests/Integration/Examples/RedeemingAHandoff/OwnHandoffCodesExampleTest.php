<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The redemption of an application's own handoff codes of
 * `docs/guides/redeeming-a-handoff.md` (SSO-4.3, SSO-4.6, SSO-8.5, SSO-9.2,
 * SSO-9.9, SSO-12.5), on the shared example harness, with the application's own
 * store bound as the handoff issuer: the package's redemption helper knows none
 * of its codes, and the application redeems them itself through
 * `HandoffRecheck`. A `link` code makes the link for the caller, and a
 * `sign_in` code then writes the person's session bound to that link and
 * records the connection's completed sign-in; each refusal is answered with its
 * reason and spends the code, whether the application's own checks refuse it (a
 * replay, the expiry, the purpose, the verifier) or the recheck does (the
 * caller of a `link`, a connection disabled since completion); and the recheck
 * refuses to run outside the application's transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(HandoffBinding::class)]
final class OwnHandoffCodesExampleTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /** @var \Tests\Integration\Examples\RedeemingAHandoff\SignIns The application's sign-ins. */
    private SignIns $signIns;

    /**
     * Create the application's table of codes, bind its store as the handoff
     * issuer, keep its sign-ins, and make the tenant's OIDC connection and the
     * person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::connection(StorageConnection::name())->create(OwnHandoffCodes::TABLE, static function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('code_digest', 64)->unique();
            $table->text('result');
            $table->string('challenge', 43);
            $table->string('linked_identity_type')->nullable();
            $table->string('linked_identity_id')->nullable();
            $table->string('link_id')->nullable();
            $table->string('identity_type')->nullable();
            $table->string('identity_id')->nullable();
            $table->string('session_id')->nullable();
            $table->string('reservation_id')->nullable();
            $table->unsignedBigInteger('expires_at');
            $table->unsignedBigInteger('consumed_at')->nullable();
        });

        $this->instance(HandoffIssuer::class, new OwnHandoffCodes($this->clock));

        $this->signIns = new SignIns;
        $this->instance(SignIns::class, $this->signIns);

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
        $this->person       = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * Drop the application's table of codes.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(OwnHandoffCodes::TABLE);

        parent::tearDown();
    }

    /**
     * The application's `link` code, which the package's helper does not know,
     * makes the link for the caller; its `sign_in` code then writes the
     * person's session, bound to that link, and records the connection's
     * completed sign-in; and the same code redeemed again is `replayed`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationRedeemsItsOwnCodes(): void
    {
        $start   = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $code    = $this->codeFor($start);
        $package = app(HandoffRedemption::class)->redeem(Purpose::LINK, self::APPLICATION, $this->connectionId, $code, self::verifierOf($start), $this->person);

        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $package->reason);
        self::assertNull(self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), $this->person));

        $links = $this->linksOf($this->person);

        self::assertCount(1, $links);
        self::assertFalse(app(ConnectionService::class)->get(self::TENANT, $this->connectionId)?->hasCompletedSignIn);

        $start = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $code  = $this->codeFor($start);

        self::assertNull(self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start)));

        $sessions = $this->signIns->sessionsOf($this->person);

        self::assertCount(1, $sessions);
        self::assertSame($links[0], $this->signIns->linkOf($sessions[0]));
        self::assertTrue(app(ConnectionService::class)->get(self::TENANT, $this->connectionId)?->hasCompletedSignIn);

        self::assertSame(FailureReason::REPLAYED, self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start)));
        self::assertSame($sessions, $this->signIns->sessionsOf($this->person));
    }

    /**
     * The application's own checks refuse a value it never issued, a code
     * presented with another verifier, at the endpoint of another purpose, or
     * after it expired; every refusal after the code was consumed spends it, so
     * the same code presented again, put right, is `replayed`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationsOwnChecksRefuseAndSpendTheCode(): void
    {
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, self::redemptions()->redeem(Purpose::LINK, 'not-a-code', 'not-a-verifier', $this->person));

        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $code  = $this->codeFor($start);

        self::assertSame(FailureReason::VERIFIER_MISMATCH, self::redemptions()->redeem(Purpose::LINK, $code, Verifier::generate()->reveal(), $this->person));
        self::assertSame(FailureReason::REPLAYED, self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), $this->person));

        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $code  = $this->codeFor($start);

        self::assertSame(FailureReason::PURPOSE_MISMATCH, self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start)));

        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $code  = $this->codeFor($start);

        $this->clock->advance(61);

        self::assertSame(FailureReason::HANDOFF_EXPIRED, self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), $this->person));
        self::assertSame([], $this->linksOf($this->person));
    }

    /**
     * The recheck refuses what the application's checks pass: a `link` code
     * presented by another caller than the identity it is bound to is
     * `identity_mismatch`, and a `sign_in` code through a connection disabled
     * since its completion is `connection_unavailable`; each spends the code,
     * and neither links nor signs anyone in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRecheckRefusesAndSpendsTheCode(): void
    {
        $start       = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $code        = $this->codeFor($start);
        $someoneElse = new IdentityReference('App\Models\User', 'person-2');

        self::assertSame(FailureReason::IDENTITY_MISMATCH, self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), $someoneElse));
        self::assertSame(FailureReason::REPLAYED, self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), $this->person));
        self::assertSame([], $this->linksOf($this->person));

        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);

        self::assertNull(self::redemptions()->redeem(Purpose::LINK, $this->codeFor($start), self::verifierOf($start), $this->person));

        $start = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $code  = $this->codeFor($start);

        self::assertTrue(app(ConnectionLifecycle::class)->disable(self::TENANT, $this->connectionId)->isSucceeded());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start)));
        self::assertSame([], $this->signIns->sessionsOf($this->person));
    }

    /**
     * Outside a transaction on the package's storage connection the recheck
     * takes no lock: it throws a `LogicException`.
     *
     * @return void
     */
    public function testTheRecheckRunsOnlyInsideTheApplicationsTransaction(): void
    {
        $this->expectException(\LogicException::class);

        app(HandoffRecheck::class)->lock(self::TENANT, $this->connectionId, self::APPLICATION);
    }

    /**
     * The application's redemption of its own codes, resolved for the request.
     *
     * @return \Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffRedemption
     */
    private static function redemptions(): OwnHandoffRedemption
    {
        return app(OwnHandoffRedemption::class);
    }

    /**
     * The code the provider's answer to the started flow is redirected with,
     * which the application's store issued.
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
}
