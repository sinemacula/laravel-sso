<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Discovery;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/discovery.md` (SSO-3.4, SSO-3.5, SSO-12.5), on
 * the shared example harness: the guide's published configuration laid over the
 * package's, an OIDC connection that `example.com` is verified for, the
 * discovery service resolved for a request, and the discovery route run over
 * HTTP. A match starts through the connection and its verifier admits the code
 * the provider's answer is issued; a miss answers alike and leads to the
 * fallback; and each refusal is shown: an application that is not registered,
 * the feature turned off, a malformed challenge, a full rate limit, and the
 * configuration check of an application that offers discovery with no fallback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiscoveryService::class)]
#[CoversClass(StartResult::class)]
final class DiscoveryExampleTest extends ExampleTestCase
{
    /** @var string Where the guide's application sends a miss. */
    private const string FALLBACK_URL = 'https://app.example.com/sign-in';

    /** @var string The route the guide's layout starts discovery on. */
    private const string ROUTE = '/auth/sso/discovery';

    /** @var string An email whose domain is verified for the connection. */
    private const string MATCH = 'jane@example.com';

    /** @var string An email whose domain nobody has claimed. */
    private const string MISS = 'jane@example.org';

    /** @var string A well formed S256 challenge, from RFC 7636's appendix. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var int The least time a discovery start takes here, in milliseconds. */
    private const int FLOOR = 50;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The connection `example.com` is verified for. */
    private string $connectionId;

    /**
     * Publish the guide's configuration, serve its route, hold every answer for
     * the least floor allowed, and make the connection whose verified domain is
     * `example.com`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->publishConfiguration();

        config()->set('sso.discovery.minimum_duration_milliseconds', self::FLOOR);
        Route::group([], __DIR__ . '/routes.php');

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);

        $this->verifyTheDomain();
    }

    /**
     * The service resolved for a request starts through the connection the
     * email's domain is verified for; the service the next request resolves is
     * another, and leads an address at a subdomain, which the exact claim does
     * not cover, to the fallback; an application that is not registered is
     * refused.
     *
     * @return void
     */
    public function testTheServiceStartsThroughTheConnectionTheDomainIsVerifiedFor(): void
    {
        // @snippet-start discovery-service
        $discovery = app(DiscoveryService::class);
        // @snippet-end discovery-service
        $match = $discovery->start(self::APPLICATION, Purpose::SIGN_IN, self::MATCH);

        self::assertTrue($match->isStarted());
        self::assertTrue($match->navigation?->isRedirect());
        self::assertSame($this->provider->endpoint('authorization'), Str::before($match->navigation->url(), '?'));

        $next = app(DiscoveryService::class);
        $miss = $next->start(self::APPLICATION, Purpose::SIGN_IN, 'jane@mail.example.com');

        self::assertNotSame($discovery, $next);
        self::assertTrue($miss->isStarted());
        self::assertSame(self::FALLBACK_URL, $miss->navigation?->url());

        $refused = $next->start('mobile', Purpose::SIGN_IN, self::MATCH);

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $refused->reason);
    }

    /**
     * The published configuration passes the `[applications]` check, as does
     * a native application's own scheme, and leads a miss to its fallback;
     * with the `discovery` feature off the application is refused as
     * `feature_disabled`; and offering discovery with no fallback fails the
     * check.
     *
     * @return void
     */
    public function testTheConfigurationOffersDiscoveryWithItsFallback(): void
    {
        self::assertStringContainsString('[applications] OK', self::checked()[1]);

        $miss = app(DiscoveryService::class)->start(self::APPLICATION, Purpose::SIGN_IN, self::MISS);

        self::assertTrue($miss->isStarted());
        self::assertTrue($miss->navigation?->isRedirect());
        self::assertSame(self::FALLBACK_URL, $miss->navigation->url());

        config()->set('sso.applications.web.discovery.fallback_url', 'com.example.app:/sign-in');

        self::assertStringContainsString('[applications] OK', self::checked()[1]);

        config()->set('sso.features.discovery', false);

        $off = app(DiscoveryService::class)->start(self::APPLICATION, Purpose::SIGN_IN, self::MATCH);

        self::assertTrue($off->isRefused());
        self::assertSame(FailureReason::FEATURE_DISABLED, $off->reason);

        config()->set('sso.features.discovery', true);
        config()->set('sso.applications.web.discovery', ['enabled' => true]);

        [$code, $output] = self::checked();

        self::assertSame(1, $code);
        self::assertStringContainsString('[applications] `sso.applications.web.discovery.fallback_url` must be an exact redirect URI', $output);
    }

    /**
     * A match answers `200` with the reference, the redirect to the provider
     * and the verifier, sent with `Cache-Control: no-store`; the provider's
     * answer is issued a code for that reference, and the verifier the client
     * kept admits it for the person linked to the subject.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheRouteStartsAMatchWhoseVerifierAdmitsItsCode(): void
    {
        $person = new IdentityReference('App\Models\User', 'person-1');

        $this->linkThroughFlow($this->provider, $this->connectionId, $person);

        $response = $this->discover(['application' => self::APPLICATION, 'email' => self::MATCH])->assertOk();

        /** @var array{reference: string, navigation: array{type: string, url: string}, verifier: string} $body */
        $body = $response->json();

        self::assertEqualsCanonicalizing(['reference', 'navigation', 'verifier'], array_keys($body));
        self::assertSame('redirect', $body['navigation']['type']);
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));

        $grant    = $this->provider->authorize($body['navigation']['url']);
        $result   = app(CompletionService::class)->callback($this->connectionId, new CompletionRequest('GET', $grant->query(), []));
        $redirect = HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'GET'));

        self::assertSame($body['reference'], $redirect->reference);

        $admitted = $this->admitDiscovered($redirect->code(), $body['verifier']);

        self::assertTrue($admitted->isAdmitted());
        self::assertEquals($person, $admitted->linkedIdentity);
    }

    /**
     * A miss answers `200` in the same shape as a match, its redirect leading
     * to the fallback, no sooner than the floor; with the client's challenge it
     * carries no verifier. Each miss reports one `discovery_no_match` naming
     * the application and the purpose, and no connection.
     *
     * @return void
     */
    public function testAMissAnswersAsAMatchDoesAndLeadsToTheFallback(): void
    {
        $failed = $this->failures();
        $began  = hrtime(true);
        $miss   = $this->discover(['application' => self::APPLICATION, 'email' => self::MISS])->assertOk();

        self::assertGreaterThanOrEqual(self::FLOOR * 1000000, hrtime(true) - $began);

        /** @var array{reference: string, navigation: array{type: string, url: string}, verifier: string} $body */
        $body = $miss->json();

        self::assertEqualsCanonicalizing(['reference', 'navigation', 'verifier'], array_keys($body));
        self::assertEquals(['type' => 'redirect', 'url' => self::FALLBACK_URL], $body['navigation']);
        self::assertStringContainsString('no-store', (string) $miss->headers->get('Cache-Control'));

        $challenged = $this->discover(['application' => self::APPLICATION, 'email' => self::MISS, 'code_challenge' => self::CHALLENGE])->assertOk();

        /** @var array<string, mixed> $challengedBody */
        $challengedBody = $challenged->json();

        self::assertEqualsCanonicalizing(['reference', 'navigation'], array_keys($challengedBody));
        self::assertCount(2, $failed);

        foreach ($failed as $event) {
            self::assertSame(FailureReason::DISCOVERY_NO_MATCH, $event->reason);
            self::assertSame(self::APPLICATION, $event->context->application);
            self::assertSame(Purpose::SIGN_IN->value, $event->context->purpose);
            self::assertNull($event->context->connectionId);
        }
    }

    /**
     * A malformed challenge and an application that is not registered each
     * answer `400` with their error; once the IP address has used its starts,
     * the next answers `429` with the wait in its body and `Retry-After`.
     *
     * @return void
     */
    public function testTheRouteAnswersEachRefusalWithItsError(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 2, 'decay_seconds' => 60]);

        $invalid = $this->discover(['application' => self::APPLICATION, 'email' => self::MATCH, 'code_challenge' => 'not-a-challenge'])->assertStatus(400);

        self::assertEquals(['error' => 'challenge_invalid'], $invalid->json());
        self::assertStringContainsString('no-store', (string) $invalid->headers->get('Cache-Control'));

        $closed = $this->discover(['application' => 'mobile', 'email' => self::MATCH])->assertStatus(400);

        self::assertEquals(['error' => 'application_not_allowed'], $closed->json());

        $limited = $this->discover(['application' => self::APPLICATION, 'email' => self::MATCH])->assertStatus(429);

        self::assertEquals(['error' => 'rate_limited', 'retry_after' => 60], $limited->json());
        self::assertSame('60', $limited->headers->get('Retry-After'));
    }

    /**
     * Lay the guide's published configuration over the package's, key by key,
     * as Laravel merges a published file with a package's.
     *
     * @return void
     */
    private function publishConfiguration(): void
    {
        /** @var array<string, mixed> $published */
        $published = require __DIR__ . '/config/sso.php';

        /** @var array<string, mixed> $package */
        $package = config('sso');

        config()->set('sso', array_replace($package, $published));
    }

    /**
     * Claim `example.com` for the connection, and verify it once the tenant has
     * published its record.
     *
     * @return void
     */
    private function verifyTheDomain(): void
    {
        $domains = app(DomainService::class);
        $claimed = $domains->claim(self::TENANT, $this->connectionId, 'example.com')->domain;

        self::assertNotNull($claimed);

        $this->dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, $domains->verify(self::TENANT, $this->connectionId, 'example.com')->status);
    }

    /**
     * Post the start to the discovery route, as the client does.
     *
     * @param  array<string, string>  $input
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function discover(array $input): TestResponse
    {
        return $this->postJson(self::ROUTE, $input);
    }

    /**
     * Admit the `sign_in` code with the verifier the client kept, in the
     * application's transaction on the package's storage connection.
     *
     * @param  string  $code
     * @param  string  $verifier
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admitDiscovered(string $code, string $verifier): RedemptionResult
    {
        $connectionId = $this->connectionId;

        return DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, self::APPLICATION, $connectionId, $code, $verifier),
        );
    }

    /**
     * Every `FlowFailed` reported from now on, as it is reported.
     *
     * @return \ArrayObject<int, \SineMacula\Laravel\Sso\Events\FlowFailed>
     */
    private function failures(): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\FlowFailed> $failed */
        $failed = new \ArrayObject;

        Event::listen(FlowFailed::class, static function (FlowFailed $event) use ($failed): void {
            $failed->append($event);
        });

        return $failed;
    }

    /**
     * Run `sso:check`, and answer its exit code and its output.
     *
     * @return array{0: int, 1: string}
     */
    private static function checked(): array
    {
        $code = Artisan::call('sso:check');

        return [$code, Artisan::output()];
    }
}
