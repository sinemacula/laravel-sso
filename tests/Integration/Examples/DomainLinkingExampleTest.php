<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Contracts\TenantMembership;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\Application\ExampleDirectory;

/**
 * The domain worked examples of the testing guide (SSO-3.1, SSO-3.2, SSO-8.8,
 * SSO-12.4): a domain claimed and verified through the fake DNS resolver,
 * linking by that verified domain turned on, and a `sign_in` whose verified
 * email the application knows reserving a link that its redemption activates;
 * a record not yet published, and an email nobody holds, each refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeDnsResolver::class)]
#[CoversClass(FakeOpenIdProvider::class)]
final class DomainLinkingExampleTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection the domain is claimed for. */
    private string $connectionId;

    /** @var \Tests\Integration\Examples\Application\ExampleDirectory The application's people. */
    private ExampleDirectory $directory;

    /**
     * Turn linking by a verified domain on, bind the application's directory
     * for the three contracts it asks, and make the provider and a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        // @snippet-start domain-linking-contracts
        config()->set('sso.features.domain_linking', true);

        $this->directory = new ExampleDirectory;

        $this->instance(LinkEmailMatcher::class, $this->directory);
        $this->instance(PrincipalScope::class, $this->directory);
        $this->instance(TenantMembership::class, $this->directory);
        // @snippet-end domain-linking-contracts
        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
    }

    /**
     * A member whose verified email is the provider's is linked by the verified
     * domain on their first sign-in: the completion reserves the link and the
     * redemption activates it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASignInReservesALinkThatItsRedemptionActivates(): void
    {
        $this->verifyTheDomain();
        $this->turnLinkingOn();

        // @snippet-start domain-linking
        $person = new IdentityReference('App\Models\User', 'person-1');

        $this->directory->add($person, 'person@example.com', self::TENANT, $this->clock->now()->subDays(2));

        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\LinkActivated> $activated */
        $activated = new \ArrayObject;

        Event::listen(LinkActivated::class, static function (LinkActivated $event) use ($activated): void {
            $activated->append($event);
        });

        $withEmail = static fn (FakeIdToken $token): FakeIdToken => $token->with('email', 'person@example.com')->with('email_verified', true);
        $start     = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect  = $this->respondAtProvider($this->provider, $this->connectionId, $start, $withEmail);
        $signedIn  = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

        self::assertEquals($person, $signedIn->linkedIdentity);
        self::assertCount(1, $activated);
        self::assertSame($signedIn->linkId, $activated->getArrayCopy()[0]->linkId);
        // @snippet-end domain-linking
    }

    /**
     * An email of the verified domain that no person of the application holds
     * reserves nothing, so the sign-in ends `unlinked`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnEmailNobodyHoldsReservesNothing(): void
    {
        $this->verifyTheDomain();
        $this->turnLinkingOn();

        // @snippet-start domain-linking-refused
        $stranger = static fn (FakeIdToken $token): FakeIdToken => $token->with('email', 'stranger@example.com')->with('email_verified', true);
        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start, $stranger);

        self::assertSame(FailureReason::UNLINKED->value, $redirect->error);
        // @snippet-end domain-linking-refused
    }

    /**
     * Claim `example.com` for the connection, and verify it once the tenant has
     * published its record, which it has not the first time it is checked.
     *
     * @return void
     */
    private function verifyTheDomain(): void
    {
        $client = Clients::browser();
        // @snippet-start domain-verify
        $domains = app(DomainService::class);
        $claimed = $domains->claim(self::TENANT, $this->connectionId, 'example.com', $client)->domain;

        self::assertNotNull($claimed);
        self::assertSame('_sso-verification.example.com', $claimed->recordName);

        // The tenant has not published the record yet
        $this->dns->absent($claimed->recordName);

        self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $domains->verify(self::TENANT, $this->connectionId, 'example.com', $client)->reason);

        // Now it has
        $this->dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, $domains->verify(self::TENANT, $this->connectionId, 'example.com', $client)->status);

        $this->dns->assertLookedUp($claimed->recordName, 2);
        // @snippet-end domain-verify
    }

    /**
     * Turn linking by a verified domain on for the connection, its issuer
     * acknowledged as one organisation's.
     *
     * @return void
     */
    private function turnLinkingOn(): void
    {
        $client = Clients::browser();
        // @snippet-start domain-linking-policy
        $changed = app(LinkingPolicyService::class)->change(self::TENANT, $this->connectionId, [
            'enabled'      => true,
            'issuer_class' => 'single_organization',
            'acknowledged' => true,
        ], $client);

        self::assertTrue($changed->isChanged());
        // @snippet-end domain-linking-policy
    }
}
