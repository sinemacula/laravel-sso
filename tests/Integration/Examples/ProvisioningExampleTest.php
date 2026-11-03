<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Integration\Examples\Application\ProvisionNewPeople;

/**
 * The provisioning worked example of the testing guide (SSO-8.6, SSO-12.4): a
 * `sign_in` of a subject nobody is linked to is offered to the application's
 * listener, which provisions a new person, and the same sign-in then completes
 * for them; with no listener, it is refused as `unlinked`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeSamlIdentityProvider::class)]
final class ProvisioningExampleTest extends ExampleTestCase
{
    /** @var \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The identity provider. */
    private FakeSamlIdentityProvider $idp;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /**
     * Make the provider and a connection that trusts it.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->idp          = new FakeSamlIdentityProvider;
        $this->connectionId = $this->makeSamlConnection($this->idp);
    }

    /**
     * The listener provisions a new person for the unlinked result, and the
     * sign-in completes for them.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAListenerProvisionsANewPerson(): void
    {
        // @snippet-start provisioning
        $listener = new ProvisionNewPeople;

        Event::listen(ResultUnlinked::class, $listener->handle(...));

        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);
        $signedIn = $this->admitSignIn($this->connectionId, $redirect, $start, 'session-1');

        self::assertCount(1, $listener->provisioned());
        self::assertEquals($listener->provisioned()[0], $signedIn->linkedIdentity);
        // @snippet-end provisioning
    }

    /**
     * With no listener, nobody is provisioned, and the sign-in fails with
     * `unlinked`: the application allows no unlinked handoff.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithNoListenerTheSignInIsUnlinked(): void
    {
        // @snippet-start provisioning-refused
        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->idp, $this->connectionId, $start);

        self::assertFalse($redirect->hasCode());
        self::assertSame(FailureReason::UNLINKED->value, $redirect->error);
        // @snippet-end provisioning-refused
    }
}
