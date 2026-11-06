<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\EvidenceSettingsService;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;
use Tests\Integration\Examples\Routes\Application\SignIns;
use Tests\Integration\Examples\Routes\Application\User;

/**
 * The further factor of the example route layout (SSO-8.7, SSO-12.5): a session
 * signed in through the routes is `pending` unless the application's own
 * further-factor policy is satisfied by the methods of the evidence the package
 * accepted, from a connection the application trusts for that factor. Accepted
 * evidence alone never activates a session, whatever the connection's evidence
 * policy accepts; and no credential leaves inside the redemption's transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AcceptedEvidence::class)]
#[CoversClass(ConnectionEvidencePolicy::class)]
#[CoversClass(HandoffRedemption::class)]
final class FurtherFactorExampleTest extends ExampleTestCase
{
    /** @var array<string, mixed> An evidence policy that accepts a password and multiple factors, and counts a password alone. */
    private const array PASSWORD_OR_MORE = ['amr' => ['mfa', 'pwd'], 'combinations' => [['amr' => ['pwd']]]];

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \Tests\Integration\Examples\Routes\Application\SignIns The application's sign-ins. */
    private SignIns $signIns;

    /**
     * Configure the base URL with the API prefix, judge evidence by each
     * connection's stored policy, register the routes, make the tenant's OIDC
     * connection, and link the person through it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.endpoints.base_url', 'https://sp.example.test/api');

        $this->app?->scoped(EvidencePolicy::class, ConnectionEvidencePolicy::class);

        $this->signIns = new SignIns($this->sessions, $this->clock);
        $this->instance(SignIns::class, $this->signIns);

        Route::prefix('api')->group(__DIR__ . '/routes.php');

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);

        $this->actingAs(User::of('person-1', self::TENANT));

        $start = $this->startOverHttp('/api/auth/sso/links/authorization-requests');

        $this->postJson('/api/auth/sso/links', $this->redemptionOf($this->completeOverHttp($start, ['pwd']), $start))->assertCreated();
    }

    /**
     * The methods the example counts as its further factor are exactly the five
     * RFC 8176 values it lists.
     *
     * @return void
     */
    public function testTheFurtherFactorMethodsAreTheApplicationsOwnList(): void
    {
        self::assertSame(['hwk', 'mfa', 'otp', 'sc', 'swk'], SignIns::FURTHER_FACTOR_METHODS);
    }

    /**
     * With no evidence accepted the session is pending, even from a trusted
     * connection whose provider asserted `mfa`: the connection has no evidence
     * policy.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNoAcceptedEvidenceLeavesTheSessionPending(): void
    {
        $this->signIns->trustFurtherFactorFrom($this->connectionId);

        self::assertSame('pending', $this->signInStatus(['pwd', 'mfa']));
    }

    /**
     * Evidence the connection's policy accepted, from a connection the
     * application does not trust for its further factor, leaves the session
     * pending, though it states `mfa`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnUntrustedConnectionsEvidenceLeavesTheSessionPending(): void
    {
        $this->setEvidencePolicy(self::PASSWORD_OR_MORE);
        $this->signIns->trustFurtherFactorFrom('a-connection-of-another-provider');

        self::assertSame('pending', $this->signInStatus(['pwd', 'mfa']));
    }

    /**
     * A password alone, accepted as evidence from a trusted connection, leaves
     * the session pending: the evidence is accepted, and its methods are not a
     * further factor.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAcceptedEvidenceOfAPasswordAloneLeavesTheSessionPending(): void
    {
        $this->setEvidencePolicy(self::PASSWORD_OR_MORE);
        $this->signIns->trustFurtherFactorFrom($this->connectionId);

        self::assertSame('pending', $this->signInStatus(['pwd']));
    }

    /**
     * A further-factor method the policy did not accept never counts: the
     * provider's `otp` is not in the connection's accepted methods.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAMethodThePolicyDidNotAcceptNeverCounts(): void
    {
        $this->setEvidencePolicy(self::PASSWORD_OR_MORE);
        $this->signIns->trustFurtherFactorFrom($this->connectionId);

        self::assertSame('pending', $this->signInStatus(['pwd', 'otp']));
    }

    /**
     * Only an accepted method the application counts, from a connection it
     * trusts for the factor, activates the session.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATrustedConnectionsAcceptedFurtherFactorActivatesTheSession(): void
    {
        $this->setEvidencePolicy(self::PASSWORD_OR_MORE);
        $this->signIns->trustFurtherFactorFrom($this->connectionId);

        self::assertSame('active', $this->signInStatus(['pwd', 'mfa']));
    }

    /**
     * No credential is issued inside a transaction on the package's storage
     * connection, where it would outlive a rollback.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoCredentialIsIssuedBeforeTheCommit(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A credential is issued only once the session\'s transaction has committed.');

        DB::connection(StorageConnection::name())->transaction(fn (): array => $this->signIns->credential('session-1'));
    }

    /**
     * Give the connection the evidence policy, as its administrator would.
     *
     * @param  array<string, mixed>  $policy
     * @return void
     */
    private function setEvidencePolicy(array $policy): void
    {
        self::assertTrue(app(EvidenceSettingsService::class)->set(self::TENANT, $this->connectionId, $policy, Clients::browser())->isSucceeded());
    }

    /**
     * Sign the person in through the routes, the provider asserting the methods
     * given, and answer the status of the credential.
     *
     * @param  list<string>  $methods
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function signInStatus(array $methods): string
    {
        $start  = $this->startOverHttp('/api/auth/sso/authorization-requests');
        $status = $this->postJson('/api/auth/sessions', $this->redemptionOf($this->completeOverHttp($start, $methods), $start))
            ->assertOk()
            ->json('status');

        return is_string($status) ? $status : self::fail('The sign-in answered no status.');
    }

    /**
     * Start a flow at the route given through the OIDC connection, and answer
     * the started body.
     *
     * @param  string  $uri
     * @return array{reference: string, navigation: array<string, mixed>, verifier: string}
     */
    private function startOverHttp(string $uri): array
    {
        /** @var array{reference: string, navigation: array<string, mixed>, verifier: string} */
        return $this->postJson($uri, ['application' => self::APPLICATION, 'connection' => $this->connectionId])->assertOk()->json();
    }

    /**
     * Have the provider grant the started flow with an ID token asserting the
     * methods given, follow the callback route, and read its redirect.
     *
     * @param  array{reference: string, navigation: array<string, mixed>, verifier: string}  $start
     * @param  list<string>  $methods
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     *
     * @throws \Random\RandomException
     */
    private function completeOverHttp(array $start, array $methods): HandoffRedirect
    {
        $url   = is_string($start['navigation']['url'] ?? null) ? $start['navigation']['url'] : self::fail('The start has no navigation URL.');
        $grant = $this->provider->authorize($url, static fn (FakeIdToken $token): FakeIdToken => $token->with('amr', $methods));

        $callback = $this->get('/api/auth/sso/connections/' . $this->connectionId . '/callback?' . $grant->query())->assertStatus(302);

        return HandoffRedirect::from($callback->headers->get('Location'));
    }

    /**
     * What the client posts to redeem the redirect's code.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\HandoffRedirect  $redirect
     * @param  array{reference: string, navigation: array<string, mixed>, verifier: string}  $start
     * @return array{application: string, connection: string, code: string, verifier: string}
     */
    private function redemptionOf(HandoffRedirect $redirect, array $start): array
    {
        return ['application' => self::APPLICATION, 'connection' => $this->connectionId, 'code' => $redirect->code(), 'verifier' => $start['verifier']];
    }
}
