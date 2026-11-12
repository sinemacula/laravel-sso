<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The own-store redemption examples of `docs/guides/redeeming-a-handoff.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(HandoffBinding::class)]
#[CoversClass(Provenance::class)]
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
     * Create the table of codes, bind the store as the handoff issuer, and make
     * the OIDC connection and person.
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
            $table->unsignedBigInteger('trust_version');
            $table->unsignedBigInteger('session_not_after')->nullable();
            $table->unsignedBigInteger('expires_at');
            $table->unsignedBigInteger('consumed_at')->nullable();
        });

        $this->instance(HandoffIssuer::class, new OwnHandoffCodes($this->clock));

        $this->signIns = new SignIns($this->clock);
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
     * The application redeems its own `link` and `sign_in` codes, which the
     * package's helper does not know.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationRedeemsItsOwnCodes(): void
    {
        $start   = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $code    = $this->codeFor($start);
        $package = app(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            self::APPLICATION,
            $this->connectionId,
            $code,
            self::verifierOf($start),
            Clients::browser(),
            new Caller($this->person),
        );

        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $package->reason);
        self::assertNull(self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), Clients::browser(), new Caller($this->person)));

        $links = $this->linksOf($this->person);

        self::assertCount(1, $links);
        self::assertFalse(app(ConnectionService::class)->get(self::TENANT, $this->connectionId)?->hasCompletedSignIn);

        $start = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $code  = $this->codeFor($start);

        self::assertNull(self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start), Clients::browser()));

        $sessions = $this->signIns->sessionsOf($this->person);

        self::assertCount(1, $sessions);
        self::assertSame($links[0], $this->signIns->linkOf($sessions[0]));
        self::assertTrue(app(ConnectionService::class)->get(self::TENANT, $this->connectionId)?->hasCompletedSignIn);

        self::assertSame(FailureReason::REPLAYED, self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start), Clients::browser()));
        self::assertSame($sessions, $this->signIns->sessionsOf($this->person));
    }

    /**
     * The application's own checks refuse a code and spend it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationsOwnChecksRefuseAndSpendTheCode(): void
    {
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, self::redemptions()->redeem(Purpose::LINK, 'not-a-code', 'not-a-verifier', Clients::browser(), new Caller($this->person)));

        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $code  = $this->codeFor($start);

        self::assertSame(
            FailureReason::VERIFIER_MISMATCH,
            self::redemptions()->redeem(Purpose::LINK, $code, Verifier::generate()->reveal(), Clients::browser(), new Caller($this->person)),
        );
        self::assertSame(FailureReason::REPLAYED, self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), Clients::browser(), new Caller($this->person)));

        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $code  = $this->codeFor($start);

        self::assertSame(FailureReason::PURPOSE_MISMATCH, self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start), Clients::browser()));

        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $code  = $this->codeFor($start);

        $this->clock->advance(61);

        self::assertSame(
            FailureReason::HANDOFF_EXPIRED,
            self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), Clients::browser(), new Caller($this->person)),
        );
        self::assertSame([], $this->linksOf($this->person));
    }

    /**
     * The recheck refuses a code the application's checks pass, and spends it.
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

        self::assertSame(
            FailureReason::IDENTITY_MISMATCH,
            self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), Clients::browser(), new Caller($someoneElse)),
        );
        self::assertSame(FailureReason::REPLAYED, self::redemptions()->redeem(Purpose::LINK, $code, self::verifierOf($start), Clients::browser(), new Caller($this->person)));
        self::assertSame([], $this->linksOf($this->person));

        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);

        self::assertNull(self::redemptions()->redeem(Purpose::LINK, $this->codeFor($start), self::verifierOf($start), Clients::browser(), new Caller($this->person)));

        $start = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $code  = $this->codeFor($start);

        self::assertTrue(app(ConnectionLifecycle::class)->disable(self::TENANT, $this->connectionId, Clients::browser())->isSucceeded());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start), Clients::browser()));
        self::assertSame([], $this->signIns->sessionsOf($this->person));
    }

    /**
     * Rows of `[change]`: every change to a SAML connection's trust.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideTrustChanges(): iterable
    {
        foreach (TrustChanges::ALL as $change) {
            yield $change => [$change];
        }
    }

    /**
     * A trust change after issuance refuses the code as
     * `connection_unavailable`, through the trust version the store kept.
     *
     * @param  string  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTrustChanges')]
    public function testATrustChangeRefusesACodeIssuedBeforeIt(string $change): void
    {
        [$idp, $connectionId] = $this->linkedThroughSaml();

        $start = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $code  = $this->respondAtProvider($idp, $connectionId, $start)->code();

        $signer = (new TrustChanges(self::TENANT, $connectionId, $this->fetcher))->make($change, $idp);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start), Clients::browser()));
        self::assertSame([], $this->signIns->sessionsOf($this->person));

        $start = $this->startFlow(Purpose::SIGN_IN, $connectionId);

        self::assertNull(
            self::redemptions()->redeem(Purpose::SIGN_IN, $this->respondAtProvider($signer, $connectionId, $start)->code(), self::verifierOf($start), Clients::browser()),
        );
        self::assertCount(1, $this->signIns->sessionsOf($this->person));
    }

    /**
     * Trusting another certificate alone refuses nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAddedCertificateRefusesNothing(): void
    {
        [$idp, $connectionId] = $this->linkedThroughSaml();

        $start = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $code  = $this->respondAtProvider($idp, $connectionId, $start)->code();

        (new TrustChanges(self::TENANT, $connectionId, $this->fetcher))->added($idp);

        self::assertNull(self::redemptions()->redeem(Purpose::SIGN_IN, $code, self::verifierOf($start), Clients::browser()));
        self::assertCount(1, $this->signIns->sessionsOf($this->person));
    }

    /**
     * A binding naming no trust version is refused as `connection_unavailable`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindingNamingNoTrustVersionIsRefused(): void
    {
        $start = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);

        self::assertNull(self::redemptions()->redeem(Purpose::LINK, $this->codeFor($start), self::verifierOf($start), Clients::browser(), new Caller($this->person)));

        $start = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $code  = app(OwnHandoffCodes::class)->find($this->codeFor($start));

        self::assertNotNull($code);

        $storage   = DB::connection(StorageConnection::name());
        $rechecked = static fn (?int $trustVersion): RecheckOutcome => $storage->transaction(static function () use ($code, $trustVersion): RecheckOutcome {
            $result  = $code->result;
            $recheck = app(HandoffRecheck::class);
            $lock    = $recheck->lock($result->tenantId, $result->connectionId, $result->application);

            return $recheck->recheck($result, new HandoffBinding($code->linkedIdentity, $code->linkId, trustVersion: $trustVersion), $lock, Clients::browser());
        });

        self::assertSame(RecheckOutcome::CONNECTION_UNAVAILABLE, $rechecked(null));
        self::assertSame(RecheckOutcome::PASSED, $rechecked($code->trustVersion));
    }

    /**
     * A limiting provider deadline caps the session and its provenance.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALimitingDeadlineCapsTheSession(): void
    {
        $deadline  = $this->clock->now()->addHours(2);
        $sessionId = $this->signedInWithDeadline($deadline);
        $token     = $this->signIns->token($sessionId);

        self::assertSame('2026-11-01T11:30:00Z', $this->signIns->notAfterOf($sessionId)?->toIso8601ZuluString());
        self::assertSame(['2026-11-01T11:30:00Z', '2026-11-01T11:30:00Z'], self::deadlinesOf($this->signIns->provenanceOf($sessionId)));
        self::assertSame($sessionId, $this->signIns->sessionOf($token));

        $this->clock->advance(7199);

        self::assertSame($sessionId, $this->signIns->sessionOf($token));

        $this->clock->advance(1);

        self::assertNull($this->signIns->sessionOf($token));
        self::assertFalse($this->signIns->isActive($sessionId));
    }

    /**
     * An ignored provider deadline leaves the session uncapped.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIgnoredDeadlineLeavesTheSessionUncapped(): void
    {
        $this->instance(ProviderSessionDeadline::class, new readonly class implements ProviderSessionDeadline {
            /**
             * The application keeps its sessions apart from the provider's.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect
             */
            #[\Override]
            public function effect(VerifiedResult $result): DeadlineEffect
            {
                unset($result);

                return DeadlineEffect::IGNORED;
            }
        });

        $sessionId = $this->signedInWithDeadline($this->clock->now()->addHours(2));
        $token     = $this->signIns->token($sessionId);

        self::assertNull($this->signIns->notAfterOf($sessionId));
        self::assertSame(['2026-11-01T11:30:00Z', null], self::deadlinesOf($this->signIns->provenanceOf($sessionId)));

        $this->clock->advance(7200);

        self::assertSame($sessionId, $this->signIns->sessionOf($token));
    }

    /**
     * The recheck throws outside a transaction on the storage connection.
     *
     * @return void
     */
    public function testTheRecheckRunsOnlyInsideTheApplicationsTransaction(): void
    {
        $this->expectException(\LogicException::class);

        app(HandoffRecheck::class)->lock(self::TENANT, $this->connectionId, self::APPLICATION);
    }

    /**
     * The application's redemption of its own codes.
     *
     * @return \Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffRedemption
     */
    private static function redemptions(): OwnHandoffRedemption
    {
        return app(OwnHandoffRedemption::class);
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
     * A SAML connection reading metadata from a URL, and its provider, with the
     * person linked through it.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider, 1: string}
     *
     * @throws \Throwable
     */
    private function linkedThroughSaml(): array
    {
        $idp          = new FakeSamlIdentityProvider;
        $connectionId = $this->makeSamlConnection($idp, ['metadata_url' => TrustChanges::METADATA_URL]);
        $start        = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        self::assertNull(
            self::redemptions()->redeem(
                Purpose::LINK,
                $this->respondAtProvider($idp, $connectionId, $start)->code(),
                self::verifierOf($start),
                Clients::browser(),
                new Caller($this->person),
            ),
        );

        return [$idp, $connectionId];
    }

    /**
     * Sign the person in through a SAML provider stating the deadline, and
     * answer the session.
     *
     * @param  \Carbon\CarbonImmutable  $deadline
     * @return string
     *
     * @throws \Throwable
     */
    private function signedInWithDeadline(CarbonImmutable $deadline): string
    {
        [$idp, $connectionId] = $this->linkedThroughSaml();

        $statement = [
            'instant'                 => $this->clock->now()->subMinute(),
            'session_index'           => '_session-1',
            'session_not_on_or_after' => $deadline,
            'class'                   => 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        ];
        $tailor = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['authn_statements' => [$statement]]);
        $start  = $this->startFlow(Purpose::SIGN_IN, $connectionId);

        self::assertNull(
            self::redemptions()->redeem(Purpose::SIGN_IN, $this->respondAtProvider($idp, $connectionId, $start, $tailor)->code(), self::verifierOf($start), Clients::browser()),
        );

        $sessions = $this->signIns->sessionsOf($this->person);

        self::assertCount(1, $sessions);

        return $sessions[0];
    }

    /**
     * The provider's session deadline and the cap the provenance records.
     *
     * @param  ?\SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return list<?string>
     */
    private static function deadlinesOf(?Provenance $provenance): array
    {
        self::assertNotNull($provenance);

        return [$provenance->providerSessionDeadline?->toIso8601ZuluString(), $provenance->sessionNotAfter?->toIso8601ZuluString()];
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
