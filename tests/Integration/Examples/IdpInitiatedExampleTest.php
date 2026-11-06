<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeServiceProvider;

/**
 * The IdP-initiated worked example of the testing guide (SSO-5.8, SSO-12.4): an
 * unsolicited SAML response, made for the service provider the connection's
 * metadata describes, signs nobody in; it sends the browser to the
 * application's start URL, which starts an ordinary SP-initiated sign-in that
 * the provider answers. The same response posted again is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeServiceProvider::class)]
#[CoversClass(FakeSamlIdentityProvider::class)]
final class IdpInitiatedExampleTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The identity provider. */
    private FakeSamlIdentityProvider $idp;

    /** @var string The connection that allows IdP-initiated sign-in. */
    private string $connectionId;

    /**
     * Turn IdP-initiated sign-in on, and make the provider and a connection
     * that allows it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        // @snippet-start idp-initiated-connection
        config()->set('sso.features.idp_initiated', true);

        $this->idp          = new FakeSamlIdentityProvider;
        $this->connectionId = $this->makeSamlConnection($this->idp, [
            'idp_initiated'           => true,
            'idp_initiated_start_url' => 'https://app.example.com/sso/start',
        ]);
        // @snippet-end idp-initiated-connection
    }

    /**
     * The unsolicited response is re-initiated to the start URL naming the
     * connection, and the sign-in the start route then begins completes for the
     * person the subject is linked to.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnUnsolicitedResponseStartsAnOrdinarySignIn(): void
    {
        $person = new IdentityReference('App\Models\User', 'person-1');

        $this->linkThroughFlow($this->idp, $this->connectionId, $person);

        $client = Clients::browser();
        // @snippet-start idp-initiated
        $metadata    = app(ServiceProviderDescriptions::class)->describe(self::TENANT, $this->connectionId);
        $sp          = FakeServiceProvider::fromMetadata((string) $metadata->body);
        $unsolicited = $this->idp->response($sp->entityId, $sp->assertionConsumerService, $this->clock->now());

        $result   = app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connectionId, $unsolicited->completionRequest(), $client);
        $location = app(CompletionResponses::class)->from($result, 'POST')->location();

        self::assertTrue($result->isReinitiated());
        self::assertSame('https://app.example.com/sso/start?connection=' . $this->connectionId, $location);

        // The start route reads the connection, and starts an ordinary sign-in
        // through it
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        $connectionId = $query['connection'] ?? null;

        self::assertIsString($connectionId);

        $start    = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);
        $signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

        self::assertEquals($person, $signedIn->linkedIdentity);
        // @snippet-end idp-initiated
    }

    /**
     * An unsolicited response is recorded once it is re-initiated, so the same
     * response posted again is rejected as `replayed`, with no redirect.
     *
     * @return void
     */
    public function testTheSameUnsolicitedResponseIsRefusedTwice(): void
    {
        $metadata    = app(ServiceProviderDescriptions::class)->describe(self::TENANT, $this->connectionId);
        $sp          = FakeServiceProvider::fromMetadata((string) $metadata->body);
        $unsolicited = $this->idp->response($sp->entityId, $sp->assertionConsumerService, $this->clock->now());

        $client = Clients::browser();
        // @snippet-start idp-initiated-replayed
        $completions = app(CompletionService::class);

        self::assertTrue($completions->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connectionId, $unsolicited->completionRequest(), $client)->isReinitiated());

        $replayed = $completions->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connectionId, $unsolicited->completionRequest(), $client);

        self::assertTrue($replayed->isRejected());
        self::assertSame(FailureReason::REPLAYED, $replayed->reason);
        self::assertNull(app(CompletionResponses::class)->from($replayed, 'POST')->location());
        // @snippet-end idp-initiated-replayed
    }

    /**
     * The response the provider makes for the service provider the metadata
     * describes is unsolicited: it names no request.
     *
     * @return void
     */
    public function testTheResponseIsMadeForTheDescribedServiceProvider(): void
    {
        $metadata = app(ServiceProviderDescriptions::class)->describe(self::TENANT, $this->connectionId);
        $sp       = FakeServiceProvider::fromMetadata((string) $metadata->body);
        $base     = 'https://sp.example.test/auth/sso/connections/' . $this->connectionId;

        self::assertSame([$base . '/metadata', $base . '/assertions'], [$sp->entityId, $sp->assertionConsumerService]);
        self::assertNull($this->idp->response($sp->entityId, $sp->assertionConsumerService)->option('in_response_to'));
    }
}
