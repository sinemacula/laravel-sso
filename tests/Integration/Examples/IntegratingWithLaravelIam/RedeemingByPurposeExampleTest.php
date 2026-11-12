<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;
use Tests\Integration\Examples\IntegratingWithLaravelIam\Contracts\ExternalIdentityLinks;

/**
 * The redemption examples of `docs/guides/integrating-with-laravel-iam.md`.
 * `laravel-authentication` is not installed, so its API runs against stand-ins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(RedemptionResult::class)]
final class RedeemingByPurposeExampleTest extends ExampleTestCase
{
    /** @var string A verifier of the right shape that answers no challenge. */
    private const string WRONG_VERIFIER = 'not-the-verifier-the-client-kept-0123456789';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection that trusts it. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /** @var \Tests\Integration\Examples\IntegratingWithLaravelIam\ExternalSessions Authentication's stand-in. */
    private ExternalSessions $authentication;

    /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\FlowFailed|\SineMacula\Laravel\Sso\Events\HandoffRedeemed> Each redemption's event. */
    private \ArrayObject $reported;

    /**
     * Bind the adapter's link contract and authentication's stand-in.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider       = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId   = $this->makeOidcConnection($this->provider);
        $this->person         = new IdentityReference('App\Models\User', 'person-1');
        $this->authentication = new ExternalSessions;
        $this->reported       = new \ArrayObject;

        app()->scoped(AdmittedRedemptions::class);
        app()->alias(AdmittedRedemptions::class, ExternalIdentityLinks::class);

        $authentication = $this->authentication;

        // The manager binds the creator to itself, so it is not static
        IlluminateAuth::extend('external', fn (): ExternalGuard => new ExternalGuard($authentication));
        config()->set('auth.guards.external', ['driver' => 'external']);
        IlluminateAuth::shouldUse('external');

        $reported = $this->reported;

        Event::listen([FlowFailed::class, HandoffRedeemed::class], static function (FlowFailed|HandoffRedeemed $event) use ($reported): void {
            $reported->append($event);
        });
    }

    /**
     * A sign-in is admitted, then established by authentication.
     *
     * @return void
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    public function testASignInIsAdmittedThenEstablishedByAuthentication(): void
    {
        $linked   = $this->linked();
        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $answer   = $this->signIn(self::APPLICATION, $this->connectionId, $redirect->code(), self::verifierOf($start));

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertFalse($answer->isFailed());
        self::assertSame('session-1', $answer->sessionId);

        $session = $this->authentication->established()['session-1'];

        self::assertSame($linked->linkId, $session->linkId);
        self::assertSame($this->connectionId, $session->connectionId);
        self::assertSame(FakeOpenIdProvider::ISSUER, $session->issuer);
        self::assertSame(FakeOpenIdProvider::SUBJECT, $session->subject);
        self::assertSame(self::TENANT, $session->tenantId);
        self::assertSame($start->reference?->value, $session->requestReference);
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());

        // Authentication keeps the provider context as JSON and hands it back
        // to the `sso` contributor, which projects it
        $json    = json_encode($session->providerContext, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION);
        $kept    = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        $context = AuthenticationContext::fromStored(is_array($kept) ? $kept : null);

        self::assertSame(AuthenticationContext::fromStored($session->providerContext), $context);
        self::assertSame(
            [$this->connectionId, self::TENANT, 'oidc', $linked->linkId],
            [$context['sso.connection'], $context['sso.tenant'], $context['sso.protocol'], $context['sso.link']],
        );
        self::assertIsString($context['sso.provider_auth_time']);
    }

    /**
     * A refusal by the package commits and spends the code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusalByThePackageCommitsAndSpendsTheCode(): void
    {
        $this->linked();

        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $refused  = $this->signIn(self::APPLICATION, $this->connectionId, $redirect->code(), self::WRONG_VERIFIER);
        $replayed = $this->signIn(self::APPLICATION, $this->connectionId, $redirect->code(), self::verifierOf($start));

        self::assertInstanceOf(RedemptionResult::class, $refused);
        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::VERIFIER_MISMATCH, $refused->reason);
        self::assertInstanceOf(RedemptionResult::class, $replayed);
        self::assertSame(FailureReason::REPLAYED, $replayed->reason);
        self::assertSame([], $this->authentication->established());
        self::assertSame([FlowFailed::class, FlowFailed::class], $this->reportedEvents());
        self::assertSame([FailureReason::VERIFIER_MISMATCH, FailureReason::REPLAYED], $this->failureReasons());
    }

    /**
     * A refusal by authentication rolls back and leaves the code unspent.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusalByAuthenticationRollsBackAndLeavesTheCodeUnspent(): void
    {
        $this->linked();

        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);

        $this->authentication->refuseWith('sso_required');

        $refusal = $this->thrownBy(fn (): mixed => $this->signIn(self::APPLICATION, $this->connectionId, $redirect->code(), self::verifierOf($start)));

        self::assertInstanceOf(ExternalSignInRefused::class, $refusal);
        self::assertSame('sso_required', $refusal->result->reason);
        self::assertSame([], $this->reportedEvents());

        $this->authentication->accept();

        $answer = $this->signIn(self::APPLICATION, $this->connectionId, $redirect->code(), self::verifierOf($start));

        self::assertInstanceOf(SignInResult::class, $answer);
        self::assertSame('session-1', $answer->sessionId);
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());
    }

    /**
     * An admitted sign-in with no linked identity is rolled back.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnUnlinkedSignInIsRolledBack(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $start    = $this->startFlow(Purpose::SIGN_IN, $this->connectionId);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $code     = $redirect->code();
        $verifier = self::verifierOf($start);

        self::assertInstanceOf(UnlinkedSignIn::class, $this->thrownBy(fn (): mixed => $this->signIn(self::APPLICATION, $this->connectionId, $code, $verifier)));
        self::assertInstanceOf(UnlinkedSignIn::class, $this->thrownBy(fn (): mixed => $this->signIn(self::APPLICATION, $this->connectionId, $code, $verifier)));
        self::assertSame([], $this->authentication->established());
        self::assertSame([], $this->reportedEvents());
    }

    /**
     * A `link` code redeemed standalone by its caller creates the link.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkIsRedeemedStandaloneWithTheCaller(): void
    {
        $start        = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $redirect     = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $application  = self::APPLICATION;
        $connectionId = $this->connectionId;
        $code         = $redirect->code();
        $verifier     = self::verifierOf($start);
        $caller       = new Caller($this->person, 'session-1'); // the signed-in person, on their session

        $client = Clients::browser();
        // @snippet-start iam-link
        $redemption = app(HandoffRedemption::class)
            ->redeem(Purpose::LINK, $application, $connectionId, $code, $verifier, $client, $caller);
        // @snippet-end iam-link
        $links = app(LinkService::class)->list($this->person);

        self::assertTrue($redemption->isRedeemed());
        self::assertFalse($redemption->isAdmitted());
        self::assertSame([$redemption->linkId], array_map(static fn (LinkSummary $link): string => $link->id, $links));
        self::assertSame(LinkState::ACTIVE, $links[0]->state);
        self::assertSame([], $this->authentication->established());
        self::assertSame([HandoffRedeemed::class], $this->reportedEvents());
    }

    /**
     * A `link` code redeemed by another caller is refused.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkRedeemedByAnotherCallerIsRefused(): void
    {
        $stranger = new Caller(new IdentityReference('App\Models\User', 'person-2'), 'session-2');
        $start    = $this->startFlow(Purpose::LINK, $this->connectionId, $this->person);
        $redirect = $this->respondAtProvider($this->provider, $this->connectionId, $start);
        $refused  = app(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            self::APPLICATION,
            $this->connectionId,
            $redirect->code(),
            self::verifierOf($start),
            Clients::browser(),
            $stranger,
        );

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::IDENTITY_MISMATCH, $refused->reason);
        self::assertSame([], app(LinkService::class)->list($this->person));
        self::assertSame([], app(LinkService::class)->list($stranger->identity));
        self::assertSame([FailureReason::IDENTITY_MISMATCH], $this->failureReasons());
    }

    /**
     * Run the adapter's `sign_in` redemption.
     *
     * @param  string  $application
     * @param  string  $connectionId
     * @param  string  $code
     * @param  string  $verifier
     * @return mixed
     */
    private function signIn(string $application, string $connectionId, string $code, string $verifier): mixed
    {
        return self::atEndpoint(['application' => $application, 'connection' => $connectionId, 'code' => $code, 'verifier' => $verifier]);
    }

    /**
     * The adapter's `sign_in` endpoint, given its input.
     *
     * @param  array{application: string, connection: string, code: string, verifier: string}  $input
     * @return mixed
     */
    private static function atEndpoint(array $input): mixed
    {
        return require __DIR__ . '/redemptions/sign-in.php';
    }

    /**
     * Link the person through a whole `link` flow, and forget what it reported.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    private function linked(): RedemptionResult
    {
        $linked = $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);

        $this->reported->exchangeArray([]);

        return $linked;
    }

    /**
     * What the call threw, failing when it threw nothing.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     */
    private function thrownBy(\Closure $call): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $thrown) {
            return $thrown;
        }

        self::fail('The call threw nothing.');
    }

    /**
     * The class of each event reported, in order.
     *
     * @return list<class-string>
     */
    private function reportedEvents(): array
    {
        return array_map(static fn (object $event): string => $event::class, array_values($this->reported->getArrayCopy()));
    }

    /**
     * The reason of each failure reported, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Events\Enums\FailureReason>
     */
    private function failureReasons(): array
    {
        $failures = array_filter($this->reported->getArrayCopy(), static fn (object $event): bool => $event instanceof FlowFailed);

        return array_values(array_map(static fn (FlowFailed $event): FailureReason => $event->reason, $failures));
    }
}
