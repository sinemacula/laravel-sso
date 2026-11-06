<?php

declare(strict_types = 1);

namespace Tests\Integration\Failures;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\MembershipStanding;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\ScriptedEmailMatcher;
use Tests\Fixtures\Linking\ScriptedPrincipalScope;
use Tests\Fixtures\Linking\ScriptedTenantMembership;
use Tests\TestCase;

/**
 * A failing statement or commit through the HTTP kernel is a 5xx (SSO-11.4) on
 * every flow and beyond its first lookup: a start, a discovery start that has
 * matched a domain, a callback and an assertion consumer service through
 * consumption, the locked transaction and the continuation, a redemption with
 * its activation of a reservation, a re-initiation, metadata and JWKS. The
 * completion's response helper turns none of them into a failure redirect, no
 * response has a `Location`, no failure event is reported, and the body shows
 * nothing of the statement.
 *
 * The real SAML and OIDC drivers run, each statement armed where it is reached
 * for certain: before the token request is after consumption and before the
 * locked transaction; the unlinked-result event is between that and the
 * continuation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationRequestService::class)]
#[CoversClass(CompletionService::class)]
#[CoversClass(CompletionResponses::class)]
#[CoversClass(DiscoveryService::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(ServiceProviderDescriptions::class)]
final class DatabaseFailureHttpTest extends TestCase
{
    use FailsDatabaseStatements, FlowRoutes, RecordsEventSequences;

    /** @var string The tenant of the connections here. */
    private const string TENANT = 'tenant-http-failures';

    /**
     * Create the tables and the routes, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->prepareFlows();
        $this->usePackageTables();
        $this->registerFlowRoutes();
        $this->startRecordingEvents();
    }

    /**
     * Rows of `[verb, table, occurrence]`: what a start reads and writes.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideStartStatements(): iterable
    {
        yield 'counting the attempt' => ['update', 'sso_rate_limits', 1];
        yield 'reading the connection' => ['select', 'sso_connections', 1];
        yield 'locking the connection' => ['select', 'sso_connections', 2];
        yield 'storing the request' => ['insert', 'sso_authorization_requests', 1];
        yield 'raising the flows version' => ['update', 'sso_connections', 1];
    }

    /**
     * A start that fails is a 5xx, never `connection_unavailable`.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideStartStatements')]
    public function testAStartIsAServerError(string $verb, string $table, int $occurrence): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');

        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError($this->flowStart($connection));
    }

    /**
     * A failed commit of a start is a 5xx too, and stores nothing.
     *
     * @return void
     */
    public function testAStartsFailedCommitIsAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');

        $this->failCommit();

        $this->assertServerError($this->flowStart($connection));

        self::assertSame(0, AuthorizationRequest::query()->useWritePdo()->count());
    }

    /**
     * With nothing failing, a discovery start that matches the domain goes to
     * its connection's provider and not the fallback, and stores its request:
     * what the rows below fail is on the path this takes.
     *
     * @return void
     */
    public function testADiscoveryStartThatMatchesGoesToItsProvider(): void
    {
        $this->flowVerifiedDomain($this->flowOidcConnection(self::TENANT, 'op-http'), 'example.com');

        $answer = $this->discoveryOf('person@example.com')->assertOk();

        self::assertStringStartsWith('https://op-http.example.test/authorize?', self::flowText($answer->json('navigation.url')));
        self::assertSame(1, AuthorizationRequest::query()->useWritePdo()->count());
    }

    /**
     * Rows of `[verb, table, occurrence]`: what a discovery start reads and
     * writes once it has counted the attempt, in the order it does.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideDiscoveryStatements(): iterable
    {
        yield 'finding the domain' => ['select', 'sso_domains', 1];
        yield 'reading the connection the domain names' => ['select', 'sso_connections', 1];
        yield 'locking the connection' => ['select', 'sso_connections', 2];
        yield 'storing the request' => ['insert', 'sso_authorization_requests', 1];
        yield 'raising the flows version' => ['update', 'sso_connections', 1];
    }

    /**
     * A discovery start that has matched a domain and then fails is a 5xx with
     * no way on: never the fallback a miss answers, which would hide the
     * failure and say the domain has no connection.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideDiscoveryStatements')]
    public function testADiscoveryStartIsAServerError(string $verb, string $table, int $occurrence): void
    {
        $this->flowVerifiedDomain($this->flowOidcConnection(self::TENANT, 'op-http'), 'example.com');

        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertDiscoveryServerError();
    }

    /**
     * A failed commit of a discovery start is the same, with nothing stored.
     *
     * @return void
     */
    public function testADiscoveryStartsFailedCommitIsAServerError(): void
    {
        $this->flowVerifiedDomain($this->flowOidcConnection(self::TENANT, 'op-http'), 'example.com');

        $this->failCommit();

        $this->assertDiscoveryServerError();
    }

    /**
     * Rows of `[verb, table, occurrence]`: what a consumption reads and writes.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideConsumptionStatements(): iterable
    {
        yield 'counting the attempt' => ['update', 'sso_rate_limits', 1];
        yield 'reading the connection' => ['select', 'sso_connections', 1];
        yield 'locking the request' => ['select', 'sso_authorization_requests', 1];
        yield 'recording the request' => ['insert', 'sso_single_use_keys', 1];
        yield 'consuming the request' => ['update', 'sso_authorization_requests', 1];
    }

    /**
     * A callback failing in its consumption is a 5xx, never `request_unknown`,
     * and goes again.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideConsumptionStatements')]
    public function testACallbackFailingInItsConsumptionIsAServerError(string $verb, string $table, int $occurrence): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');
        $start      = $this->startedFlow($connection);
        $grant      = $this->flowGrant($connection, $start);

        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError($this->deliverGrant($connection, $grant));

        self::assertNull(AuthorizationRequest::query()->useWritePdo()->where('reference', $start['reference'])->sole()->consumed_at);

        $this->completedCode($this->deliverGrant($connection, $grant));
    }

    /**
     * A failed commit of the consumption is a 5xx too.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACallbacksFailedConsumptionCommitIsAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');
        $grant      = $this->flowGrant($connection, $this->startedFlow($connection));

        $this->failCommit();

        $this->assertServerError($this->deliverGrant($connection, $grant));
    }

    /**
     * Rows of `[verb, table, occurrence]`: what the locked transaction reads
     * and writes.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideLockedStatements(): iterable
    {
        yield 'locking the connection' => ['select', 'sso_connections', 1];
        yield 'locking the request' => ['select', 'sso_authorization_requests', 1];
        yield 'resolving the link' => ['select', 'sso_links', 1];
        yield 'stamping the request' => ['update', 'sso_authorization_requests', 1];
    }

    /**
     * A callback failing in its locked transaction, past a valid token, is a
     * 5xx with no failure redirect.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideLockedStatements')]
    public function testACallbackFailingUnderItsLocksIsAServerError(string $verb, string $table, int $occurrence): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');
        $start      = $this->startedFlow($connection);

        $this->beforeTokenRequest = fn () => $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError($this->completeFlow($connection, $start));
    }

    /**
     * A failed commit of the locked transaction is a 5xx too.
     *
     * @return void
     */
    public function testACallbacksFailedLockedCommitIsAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');
        $start      = $this->startedFlow($connection);

        $this->beforeTokenRequest = fn () => $this->failCommit();

        $this->assertServerError($this->completeFlow($connection, $start));
    }

    /**
     * A callback failing to issue its code in the continuation is a 5xx, and a
     * listener that was offered the result has been told nothing of a failure.
     *
     * @return void
     */
    public function testACallbackFailingToIssueItsCodeIsAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');
        $start      = $this->startedFlow($connection);

        Event::listen(ResultUnlinked::class, fn () => $this->failStatement(self::onTable('insert', 'sso_handoff_codes')));

        $this->assertServerError($this->completeFlow($connection, $start));
    }

    /**
     * A failed commit of the continuation is a 5xx too.
     *
     * @return void
     */
    public function testACallbacksFailedContinuationCommitIsAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');
        $start      = $this->startedFlow($connection);

        Event::listen(ResultUnlinked::class, fn () => $this->failCommit());

        $this->assertServerError($this->completeFlow($connection, $start));
    }

    /**
     * An assertion consumer service failing in its consumption is a 5xx, never
     * an invalid response.
     *
     * @return void
     */
    public function testAnAssertionFailingInItsConsumptionIsAServerError(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-http');
        $start      = $this->startedFlow($connection);

        $this->failStatement(self::onTable('update', 'sso_authorization_requests'));

        $this->assertServerError($this->completeFlow($connection, $start));
    }

    /**
     * An assertion that cannot be recorded against replay, the second record
     * after its request's, is a 5xx, never `replayed` and never a pass.
     *
     * @return void
     */
    public function testAnAssertionFailingToRecordItselfIsAServerError(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-http');
        $start      = $this->startedFlow($connection);

        $this->failStatement(self::onTable('insert', 'sso_single_use_keys'), 2);

        $this->assertServerError($this->completeFlow($connection, $start));
    }

    /**
     * Rows of `[verb, table, occurrence]`: what a redemption reads and writes.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideRedemptionStatements(): iterable
    {
        yield 'counting the attempt' => ['update', 'sso_rate_limits', 1];
        yield 'finding the code' => ['select', 'sso_handoff_codes', 1];
        yield 'locking the code' => ['select', 'sso_handoff_codes', 2];
        yield 'recording the code' => ['insert', 'sso_single_use_keys', 1];
        yield 'consuming the code' => ['update', 'sso_handoff_codes', 1];
    }

    /**
     * A redemption that fails is a 5xx, never a failed redemption, and the code
     * redeems when tried again.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideRedemptionStatements')]
    public function testARedemptionIsAServerError(string $verb, string $table, int $occurrence): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError($this->flowRedeem($connection, 'sign_in', $code, $start['verifier']));

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();
    }

    /**
     * A failed commit of a redemption is a 5xx too, and undoes it.
     *
     * @return void
     */
    public function testARedemptionsFailedCommitIsAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        $this->failCommit();

        $this->assertServerError($this->flowRedeem($connection, 'sign_in', $code, $start['verifier']));

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();
    }

    /**
     * A redemption that cannot activate its reservation is a 5xx, never a
     * failed redemption: the reservation is still one, and the code redeems and
     * activates it when tried again.
     *
     * @return void
     */
    public function testARedemptionFailingToActivateItsReservationIsAServerError(): void
    {
        $connection = $this->reservingConnection();
        $start      = $this->startedFlow($connection);
        $code       = $this->completedCode($this->completeFlow($connection, $start, self::verifiedEmail()));

        self::assertSame(LinkState::RESERVED, Link::query()->useWritePdo()->sole()->state);

        $this->failStatement(self::onTable('update', 'sso_links'));

        $this->assertServerError($this->flowRedeem($connection, 'sign_in', $code, $start['verifier']));

        self::assertSame(LinkState::RESERVED, Link::query()->useWritePdo()->sole()->state);

        $this->flowRedeem($connection, 'sign_in', $code, $start['verifier'])->assertOk();

        self::assertSame(LinkState::ACTIVE, Link::query()->useWritePdo()->sole()->state);
    }

    /**
     * A `link` that cannot create its link is a 5xx, never
     * `subject_already_linked`.
     *
     * @return void
     */
    public function testALinkFailingToCreateItsLinkIsAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');
        $identity   = new IdentityReference('App\Models\User', 'person-http');
        $start      = $this->startedFlow($connection, 'link', $identity);
        $code       = $this->completedCode($this->completeFlow($connection, $start));

        $this->failStatement(self::onTable('insert', 'sso_links'));

        $this->assertServerError($this->flowRedeem($connection, 'link', $code, $start['verifier'], $identity));
    }

    /**
     * A re-initiation that cannot record its assertion is a 5xx, never a
     * refusal.
     *
     * @return void
     */
    public function testAReinitiationIsAServerError(): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-http', ['idp_initiated' => true, 'idp_initiated_start_url' => self::FLOW_START_URL]);

        $this->failStatement(self::onTable('insert', 'sso_single_use_keys'));

        $this->assertServerError($this->postSamlResponse($connection, $this->flowSamlResponse($connection)));
    }

    /**
     * Rows of `[verb, table, occurrence]`: what SAML metadata reads, the keys
     * of each use after the connection.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function provideMetadataStatements(): iterable
    {
        yield 'reading the connection' => ['select', 'sso_connections', 1];
        yield 'reading the signing keys' => ['select', 'sso_keys', 1];
        yield 'reading the encryption keys' => ['select', 'sso_keys', 2];
    }

    /**
     * Metadata that cannot read its connection or its keys is a 5xx, never a
     * 404 and never a document missing the keys.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideMetadataStatements')]
    public function testMetadataIsAServerError(string $verb, string $table, int $occurrence): void
    {
        $connection = $this->flowSamlConnection(self::TENANT, 'idp-http');

        $this->failStatement(self::onTable($verb, $table), $occurrence);

        $this->assertServerError($this->sendFlowRequest('GET', '/sso/metadata/' . self::TENANT . "/{$connection->id}"));
    }

    /**
     * JWKS that cannot read its keys is a 5xx, never a 404.
     *
     * @return void
     */
    public function testJwksIsAServerError(): void
    {
        $connection = $this->flowOidcConnection(self::TENANT, 'op-http', settings: ['client_authentication' => 'private_key_jwt']);

        app(KeyService::class)->addNext(self::TENANT, $connection->id, KeyUse::CLIENT_ASSERTION, Clients::browser(), KeyType::EC);

        $this->failStatement(self::onTable('select', 'sso_keys'));

        $this->assertServerError($this->sendFlowRequest('GET', "/sso/jwks/{$connection->id}"));
    }

    /**
     * Ask to start a discovery for the email.
     *
     * @param  string  $email
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function discoveryOf(string $email): TestResponse
    {
        return $this->sendFlowRequest('POST', '/sso/discover', ['email' => $email]);
    }

    /**
     * Assert a discovery start is the 5xx of the one injected failure, with no
     * way on and no request stored.
     *
     * @return void
     */
    private function assertDiscoveryServerError(): void
    {
        $answer = $this->discoveryOf('person@example.com');

        $this->assertServerError($answer);

        self::assertNull($answer->json('navigation.url'));
        self::assertSame(0, AuthorizationRequest::query()->useWritePdo()->count());
    }

    /**
     * An OIDC connection whose completion reserves a link for the person a
     * verified email names, with what a reservation stands on bound: the
     * package's link store, the contracts that accept the person, linking by a
     * verified domain on, and the verified claim of `example.com`.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function reservingConnection(): Connection
    {
        config()->set('sso.features.domain_linking', true);

        $now = CarbonImmutable::parse(self::FLOW_NOW);

        $this->app?->instance(LinkEmailMatcher::class, new ScriptedEmailMatcher(LinkEmailMatch::exactlyOne(new IdentityReference('App\Models\User', 'person-http'))));
        $this->app?->instance(PrincipalScope::class, new ScriptedPrincipalScope);
        $this->app?->instance(TenantMembership::class, new ScriptedTenantMembership(MembershipStanding::accepted($now->subDays(2))));

        $connection = $this->flowOidcConnection(self::TENANT, 'op-http');

        $connection->forceFill([
            'linking_enabled'         => true,
            'linking_issuer_class'    => 'single_organization',
            'linking_acknowledged_at' => $now->subDay(),
        ])->save();

        $this->makeDomain($connection, 'example.com', [
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => 'example.com',
            'verified_at'              => $now->subDay(),
            'verification_generation'  => 1,
            'last_successful_check_at' => $now,
        ]);

        return $connection;
    }

    /**
     * What has an ID token assert the person's email, verified.
     *
     * @return \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private static function verifiedEmail(): \Closure
    {
        return static fn (FakeIdToken $token): FakeIdToken => $token->with('email', 'person@example.com')->with('email_verified', true);
    }

    /**
     * Assert the response is the 5xx of the one injected failure: no redirect,
     * nothing of the statement, and no failure event.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return void
     */
    private function assertServerError(TestResponse $response): void
    {
        $response->assertServerError();

        self::assertSame(1, $this->databaseFailuresFired());
        self::assertFalse($response->baseResponse->headers->has('Location'));

        foreach ([self::INJECTED_FAILURE, 'sso_', 'select ', 'insert ', 'update '] as $leak) {
            self::assertStringNotContainsString($leak, (string) $response->baseResponse->getContent());
        }

        $this->assertNoFailure();
    }
}
