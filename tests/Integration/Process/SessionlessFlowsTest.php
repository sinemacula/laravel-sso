<?php

declare(strict_types = 1);

namespace Tests\Integration\Process;

use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use Tests\Concerns\FlowRoutes;
use Tests\Fixtures\Clients;
use Tests\TestCase;

/**
 * Integration tests that every flow runs without a session.
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
final class SessionlessFlowsTest extends TestCase
{
    use FlowRoutes;

    /** @var int How many times the session has been touched. */
    private int $sessionTouches = 0;

    /**
     * Create the routes and contracts, and make touching the session fail.
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
        $this->refuseTheSession();
    }

    /**
     * Every route runs with no middleware and the kernel starts no session.
     *
     * @return void
     */
    public function testTheRoutesHaveNoMiddleware(): void
    {
        $routes = array_filter(Route::getRoutes()->getRoutes(), static fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'sso/'));

        self::assertCount(7, $routes);

        foreach ($routes as $route) {
            self::assertSame([], $route->gatherMiddleware(), $route->uri());
        }
    }

    /**
     * A SAML start, assertion consumer service and redemption need no session.
     *
     * @return void
     */
    public function testASamlSignInNeedsNoSession(): void
    {
        $connection = $this->flowSamlConnection('tenant-saml', 'idp-sessionless');
        $start      = $this->startedFlow($connection);
        $completed  = $this->completeFlow($connection, $start);
        $redeemed   = $this->flowRedeem($connection, 'sign_in', $this->completedCode($completed), $start['verifier'])->assertOk();

        self::assertSame(['redeemed', 'tenant-saml', $connection->id, $start['reference']], [
            $redeemed->json('status'),
            $redeemed->json('tenant'),
            $redeemed->json('connection'),
            $redeemed->json('reference'),
        ]);

        $this->assertNoSession($completed, $redeemed);
    }

    /**
     * An OIDC start, callback and redemption need no session.
     *
     * @return void
     */
    public function testAnOidcSignInNeedsNoSession(): void
    {
        $connection = $this->flowOidcConnection('tenant-oidc', 'op-sessionless');
        $start      = $this->startedFlow($connection);
        $completed  = $this->completeFlow($connection, $start);
        $redeemed   = $this->flowRedeem($connection, 'sign_in', $this->completedCode($completed), $start['verifier'])->assertOk();

        self::assertSame(['redeemed', 'tenant-oidc', $connection->id, $start['reference']], [
            $redeemed->json('status'),
            $redeemed->json('tenant'),
            $redeemed->json('connection'),
            $redeemed->json('reference'),
        ]);

        $this->assertNoSession($completed, $redeemed);
    }

    /**
     * A discovery start, matched or not, needs no session.
     *
     * @return void
     */
    public function testADiscoveryStartNeedsNoSession(): void
    {
        $connection = $this->flowOidcConnection('tenant-discovery', 'op-discovery');

        $this->flowVerifiedDomain($connection, 'discovery.example.com');

        $match         = $this->sendFlowRequest('POST', '/sso/discover', ['email' => 'person@discovery.example.com'])->assertOk();
        $miss          = $this->sendFlowRequest('POST', '/sso/discover', ['email' => 'person@nowhere.example.com'])->assertOk();
        $authorization = $this->flowProvider($connection)->endpoint('authorization');

        self::assertNotSame('', $authorization);
        self::assertStringStartsWith($authorization, self::flowText($match->json('navigation.url')));
        self::assertSame(self::FLOW_FALLBACK_URL, $miss->json('navigation.url'));

        /** @var array{reference: string, verifier: string, navigation: array{type: string, url: string}} $start */
        $start     = $match->json();
        $completed = $this->completeFlow($connection, $start);
        $redeemed  = $this->flowRedeem($connection, 'sign_in', $this->completedCode($completed), $start['verifier'], null, self::DISCOVERING_APPLICATION)->assertOk();

        self::assertSame('tenant-discovery', $redeemed->json('tenant'));

        $this->assertNoSession($match, $miss, $completed, $redeemed);
    }

    /**
     * Metadata and public keys are served without a session.
     *
     * @return void
     */
    public function testMetadataAndJwksNeedNoSession(): void
    {
        $saml = $this->flowSamlConnection('tenant-saml', 'idp-metadata');
        $oidc = $this->flowOidcConnection('tenant-oidc', 'op-metadata', settings: ['client_authentication' => 'private_key_jwt']);

        app(KeyService::class)->addNext('tenant-oidc', $oidc->id, KeyUse::CLIENT_ASSERTION, Clients::browser(), KeyType::EC);

        $samlMetadata = $this->sendFlowRequest('GET', "/sso/metadata/tenant-saml/{$saml->id}")->assertOk();
        $oidcMetadata = $this->sendFlowRequest('GET', "/sso/metadata/tenant-oidc/{$oidc->id}")->assertOk();
        $jwks         = $this->sendFlowRequest('GET', "/sso/jwks/{$oidc->id}")->assertOk();

        self::assertStringStartsWith('<md:EntityDescriptor', (string) $samlMetadata->baseResponse->getContent());
        self::assertSame(["https://sp.example.test/auth/sso/connections/{$oidc->id}/callback"], $oidcMetadata->json('redirect_uris'));
        self::assertCount(1, (array) $jwks->json('keys'));

        $this->assertNoSession($samlMetadata, $oidcMetadata, $jwks);
    }

    /**
     * A redemption of each purpose needs no session.
     *
     * @return void
     */
    public function testARedemptionOfEachPurposeNeedsNoSession(): void
    {
        $connection = $this->flowOidcConnection('tenant-purposes', 'op-purposes');
        $identity   = new IdentityReference('App\Models\User', 'person-purposes');
        $linkId     = $this->linkedThroughFlow($connection, $identity);

        $signedIn       = $this->signedIn($connection);
        $reauthenticate = $this->reauthenticatedThroughFlow($connection, $identity, $linkId);

        self::assertSame([$identity->jsonSerialize(), $linkId], [$signedIn['linked'], $signedIn['link_id']]);
        self::assertSame('redeemed', $reauthenticate['status']);
        self::assertSame(1, $this->flowSessions->renewals());

        $this->assertNoSession();
    }

    /**
     * An IdP-initiated response redirects to the start without a session or
     * row.
     *
     * @return void
     */
    public function testAReinitiationNeedsNoSession(): void
    {
        $connection = $this->flowSamlConnection('tenant-saml', 'idp-reinitiate', [
            'idp_initiated'           => true,
            'idp_initiated_start_url' => self::FLOW_START_URL,
        ]);

        $answer = $this->postSamlResponse($connection, $this->flowSamlResponse($connection));

        $answer->assertStatus(303);

        self::assertSame(self::FLOW_START_URL . '?connection=' . $connection->id, $answer->baseResponse->headers->get('Location'));
        self::assertSame(0, AuthorizationRequest::query()->useWritePdo()->count());

        $this->assertNoSession($answer);
    }

    /**
     * The request row holds only digests and ciphertext of the flow's secrets.
     *
     * @return void
     */
    public function testTheStateOfAFlowIsInItsRequestRow(): void
    {
        $connection = $this->flowOidcConnection('tenant-state', 'op-state');
        $start      = $this->startedFlow($connection);
        $query      = self::queryOf($start);
        $state      = self::flowText($query['state']);
        $nonce      = self::flowText($query['nonce']);

        $row = AuthorizationRequest::query()->useWritePdo()->where('reference', $start['reference'])->sole();

        self::assertSame([hash('sha256', $state), hash('sha256', $nonce), $connection->id], [$row->state_digest, $row->nonce_digest, $row->connection_id]);

        $stored = (string) json_encode($row->getAttributes());

        foreach ([$state, $nonce, $start['verifier']] as $value) {
            self::assertStringNotContainsString($value, $stored);
        }

        $this->assertNoSession();
    }

    /**
     * With the request row gone, the same answer is a `400` with no redirect.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFlowWithoutItsRequestRowIsRefused(): void
    {
        $connection = $this->flowOidcConnection('tenant-state', 'op-state-gone');
        $start      = $this->startedFlow($connection);
        $grant      = $this->flowGrant($connection, $start);

        AuthorizationRequest::query()->useWritePdo()->where('reference', $start['reference'])->delete();

        $answer = $this->deliverGrant($connection, $grant);

        $answer->assertStatus(400);

        self::assertFalse($answer->baseResponse->headers->has('Location'));

        $this->assertNoSession($answer);
    }

    /**
     * Bind a session that fails and counts when touched.
     *
     * Earlier bindings go first, so nothing is rebound through it.
     *
     * @return void
     */
    private function refuseTheSession(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        foreach (['session', 'session.store'] as $abstract) {

            unset($app[$abstract]);

            $app->singleton($abstract, function (): never {

                $this->sessionTouches++;

                throw new \LogicException('The session was touched.');
            });
        }
    }

    /**
     * Assert no session was resolved, started, held or set as a cookie.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  ...$responses
     * @return void
     */
    private function assertNoSession(TestResponse ...$responses): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        self::assertSame(0, $this->sessionTouches);
        self::assertFalse($app->resolved('session'));
        self::assertFalse($app->resolved('session.store'));
        self::assertFalse($app->make('request')->hasSession());

        foreach ($responses as $response) {
            self::assertFalse($response->baseResponse->headers->has('Set-Cookie'));
        }
    }
}
