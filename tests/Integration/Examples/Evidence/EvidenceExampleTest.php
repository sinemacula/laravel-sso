<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Evidence;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\EvidenceSettingsService;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/evidence.md` (SSO-8.7, SSO-12.5), on the shared
 * example harness: the application opts in by binding the package's policy in
 * its service provider, gives an OIDC and a SAML connection each its evidence
 * policy, and reads the evidence a sign-in's redemption accepted. Each asserts
 * what a redemption then carries: only the accepted methods, as asserted and
 * each once, when an accepted combination is satisfied, and no evidence at all
 * when none is, when the connection names no policy, or when the application
 * never opted in. A change asked without trust freshness, of a connection the
 * tenant does not have, or naming what the protocol or the ceiling does not
 * allow, is refused and writes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-import-type IdTokenTailor from \Tests\Integration\Examples\ExampleTestCase
 * @phpstan-import-type ResponseTailor from \Tests\Integration\Examples\ExampleTestCase
 *
 * @internal
 */
#[CoversClass(ConnectionEvidencePolicy::class)]
#[CoversClass(EvidenceSettingsService::class)]
#[CoversClass(AcceptedEvidence::class)]
final class EvidenceExampleTest extends ExampleTestCase
{
    /** @var string The class a provider states for multiple factors, as REFEDS profiles it. */
    private const string REFEDS_MFA = 'https://refeds.org/profile/mfa';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var string The OIDC connection that trusts it, through which the person is linked. */
    private string $connectionId;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /** @var int How many sessions the test has signed in, naming the next. */
    private int $signIns;

    /**
     * Make the tenant's OIDC connection and link the person through it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider     = new FakeOpenIdProvider(clock: $this->clock);
        $this->connectionId = $this->makeOidcConnection($this->provider);
        $this->person       = new IdentityReference('App\Models\User', 'person-1');
        $this->signIns      = 0;

        $this->linkThroughFlow($this->provider, $this->connectionId, $this->person);
    }

    /**
     * Until the application binds the package's policy, the default accepts
     * nothing: a connection's stored policy is written, and a provider stating
     * every method it accepts still gives no evidence.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNothingCountsUntilTheApplicationOptsIn(): void
    {
        self::assertInstanceOf(InsufficientEvidence::class, app(EvidencePolicy::class));
        self::assertTrue($this->setPolicy(['amr' => ['pwd', 'otp'], 'combinations' => [['amr' => ['pwd', 'otp']]]])->isChanged());

        self::assertNull($this->signInThroughOidc(['pwd', 'otp'])->evidence);
    }

    /**
     * The service provider binds the package's policy, scoped, so one request
     * or job judges by one instance; with no policy stored on the connection it
     * still accepts nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheBindingJudgesByEachConnectionsPolicy(): void
    {
        app()->register(AppServiceProvider::class);

        self::assertInstanceOf(ConnectionEvidencePolicy::class, app(EvidencePolicy::class));
        self::assertSame(app(EvidencePolicy::class), app(EvidencePolicy::class));

        self::assertNull($this->signInThroughOidc(['pwd', 'otp'])->evidence);
    }

    /**
     * An OIDC connection's policy is written whole and reported by name; the
     * same policy again is `unchanged`. A result counts only by an accepted
     * combination, and then carries only the accepted methods it stated: a
     * password with a one-time code, or a hardware key with the class, counts;
     * a password alone, or the hardware key with another class, does not.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGivingAnOidcConnectionItsPolicy(): void
    {
        app()->register(AppServiceProvider::class);

        $tenantId     = self::TENANT;
        $connectionId = $this->connectionId;

        $client = Clients::browser();
        // @snippet-start oidc-evidence-policy
        $result = app(EvidenceSettingsService::class)->set($tenantId, $connectionId, [
            'amr'          => ['pwd', 'otp', 'hwk'],
            'acr'          => ['urn:example:loa:2'],
            'combinations' => [
                ['amr' => ['pwd', 'otp']],
                ['amr' => ['hwk'], 'acr' => 'urn:example:loa:2'],
            ],
        ], $client);
        // @snippet-end oidc-evidence-policy
        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame(['evidence.acr', 'evidence.amr', 'evidence.combinations'], $result->changedSettings);

        $stored = app(EvidenceSettingsService::class)->get($tenantId, $connectionId) ?? self::fail('The connection has no policy.');

        self::assertSame(['pwd', 'otp', 'hwk'], $stored['amr'] ?? null);
        self::assertSame(ConnectionStatus::UNCHANGED, $this->setPolicy($stored)->status);

        self::assertSame(['pwd', 'otp'], $this->signInThroughOidc(['pwd', 'sms', 'otp'])->evidence?->methods());
        self::assertSame(['hwk'], $this->signInThroughOidc(['hwk'], 'urn:example:loa:2')->evidence?->methods());
        self::assertNull($this->signInThroughOidc(['pwd'])->evidence);
        self::assertNull($this->signInThroughOidc(['hwk'], 'urn:example:loa:1')->evidence);
    }

    /**
     * A change is refused, and nothing written, when the caller's
     * authentication is too old for `sso.connection.trust`, when the tenant has
     * no such connection, and when the policy's maximum age is above the
     * ceiling; an empty policy clears what is stored.
     *
     * @return void
     */
    public function testAChangeIsRefusedOrClears(): void
    {
        $policy     = ['amr' => ['pwd'], 'combinations' => [['amr' => ['pwd']]]];
        $staleTrust = FakeFreshness::fresh()->staleFor(FreshnessOperation::CONNECTION_TRUST);

        $this->instance(Freshness::class, $staleTrust);

        $stale = $this->setPolicy($policy);

        $staleTrust->assertAsked(FreshnessOperation::CONNECTION_TRUST);
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $stale->reason);
        self::assertSame([], app(EvidenceSettingsService::class)->get(self::TENANT, $this->connectionId));

        $this->instance(Freshness::class, $this->freshness);

        $elsewhere = app(EvidenceSettingsService::class)->set('tenant-2', $this->connectionId, $policy, Clients::browser());
        $overlong  = $this->setPolicy([...$policy, 'max_age_seconds' => 901]);

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $elsewhere->reason);
        self::assertTrue($overlong->isInvalid());
        self::assertContains(['max_age_seconds', 'not_allowed'], self::violationsOf($overlong));
        self::assertSame([], app(EvidenceSettingsService::class)->get(self::TENANT, $this->connectionId));

        self::assertTrue($this->setPolicy($policy)->isChanged());
        self::assertSame(['evidence.amr', 'evidence.combinations'], $this->setPolicy([])->changedSettings);
        self::assertSame([], app(EvidenceSettingsService::class)->get(self::TENANT, $this->connectionId));
    }

    /**
     * A SAML connection names its accepted classes and combinations of one
     * class each: a response stating the class gives evidence with no methods
     * and the class as its raw context, and one stating another class gives
     * none. A SAML policy naming `amr` is invalid.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGivingASamlConnectionItsPolicy(): void
    {
        app()->register(AppServiceProvider::class);

        $idp              = new FakeSamlIdentityProvider;
        $tenantId         = self::TENANT;
        $samlConnectionId = $this->makeSamlConnection($idp);

        $this->linkThroughFlow($idp, $samlConnectionId, $this->person);

        $client = Clients::browser();
        // @snippet-start saml-evidence-policy
        $result = app(EvidenceSettingsService::class)->set($tenantId, $samlConnectionId, [
            'authn_context_class_ref' => ['https://refeds.org/profile/mfa'],
            'combinations'            => [
                ['authn_context_class_ref' => 'https://refeds.org/profile/mfa'],
            ],
        ], $client);
        // @snippet-end saml-evidence-policy
        self::assertSame(['evidence.authn_context_class_ref', 'evidence.combinations'], $result->changedSettings);

        $evidence = $this->signInThroughSaml($idp, $samlConnectionId, self::REFEDS_MFA)->evidence;

        self::assertNotNull($evidence);
        self::assertSame($samlConnectionId, $evidence->connectionId);
        self::assertSame([], $evidence->methods());
        self::assertSame(self::REFEDS_MFA, $evidence->rawContext());
        self::assertNull($this->signInThroughSaml($idp, $samlConnectionId, FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT)->evidence);

        $invalid = app(EvidenceSettingsService::class)->set($tenantId, $samlConnectionId, ['amr' => ['pwd'], 'combinations' => [['amr' => ['pwd']]]], Clients::browser());

        self::assertSame(FailureReason::SETTINGS_INVALID, $invalid->reason);
        self::assertContains(['amr', 'unsupported'], self::violationsOf($invalid));
    }

    /**
     * The evidence a sign-in's redemption carries names the connection and the
     * provider's authentication time, the accepted methods as asserted and each
     * once, and the raw class, though the policy lists it nowhere. A dump or
     * `json_encode()` shows only how many methods, and it refuses to be
     * serialised.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testReadingTheAcceptedEvidence(): void
    {
        app()->register(AppServiceProvider::class);

        $this->setPolicy(['amr' => ['pwd', 'otp'], 'combinations' => [['amr' => ['pwd', 'otp']]]]);

        $result = $this->signInThroughOidc(['otp', 'pwd', 'otp', 'sms'], 'urn:example:loa:3');

        // @snippet-start accepted-evidence
        $evidence = $result->evidence; // ?AcceptedEvidence

        $connectionId    = $evidence?->connectionId;    // the credential reference
        $authenticatedAt = $evidence?->authenticatedAt; // when the provider authenticated the person
        $methods         = $evidence?->methods();       // only the accepted RFC 8176 methods, as asserted, each once
        $rawContext      = $evidence?->rawContext();    // the raw acr or AuthnContextClassRef, as data, listed or not
        // @snippet-end accepted-evidence
        self::assertNotNull($authenticatedAt);
        self::assertSame($this->connectionId, $connectionId);
        self::assertSame(self::NOW, $authenticatedAt->toIso8601ZuluString());
        self::assertSame(['otp', 'pwd'], $methods);
        self::assertSame('urn:example:loa:3', $rawContext);

        self::assertEquals(
            ['connection_id' => $this->connectionId, 'authenticated_at' => self::NOW, 'methods' => 2, 'raw_context' => '[redacted]'],
            json_decode((string) json_encode($evidence), true),
        );

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Accepted evidence cannot be serialised.');

        serialize($evidence);
    }

    /**
     * Set the OIDC connection's evidence policy, as its administrator would.
     *
     * @param  array<array-key, mixed>  $policy
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function setPolicy(array $policy): ConnectionResult
    {
        return app(EvidenceSettingsService::class)->set(self::TENANT, $this->connectionId, $policy, Clients::browser());
    }

    /**
     * Sign the person in through the OIDC connection, the provider stating the
     * methods and the class given, and answer the admitted redemption.
     *
     * @param  list<string>  $methods
     * @param  ?string  $class
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    private function signInThroughOidc(array $methods, ?string $class = null): RedemptionResult
    {
        $tailor = static function (FakeIdToken $token) use ($methods, $class): FakeIdToken {

            $token = $token->with('amr', $methods);

            return $class === null ? $token : $token->with('acr', $class);
        };

        return $this->admitted($this->provider, $this->connectionId, $tailor);
    }

    /**
     * Sign the person in through the SAML connection, the provider stating the
     * class given, and answer the admitted redemption.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $idp
     * @param  string  $connectionId
     * @param  string  $class
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    private function signInThroughSaml(FakeSamlIdentityProvider $idp, string $connectionId, string $class): RedemptionResult
    {
        $now       = $this->clock->now();
        $statement = ['instant' => $now->subMinute(), 'session_index' => '_session-1', 'session_not_on_or_after' => $now->addHours(8), 'class' => $class];
        $tailor    = static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['authn_statements' => [$statement]]);

        return $this->admitted($idp, $connectionId, $tailor);
    }

    /**
     * Start a `sign_in` through the connection, have the provider answer it
     * with the tailor, and admit the code into a new session.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider|\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $provider
     * @param  string  $connectionId
     * @param  IdTokenTailor|ResponseTailor  $tailor
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    private function admitted(FakeOpenIdProvider|FakeSamlIdentityProvider $provider, string $connectionId, \Closure $tailor): RedemptionResult
    {
        $start    = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $redirect = $this->respondAtProvider($provider, $connectionId, $start, $tailor);
        $result   = $this->admitSignIn($connectionId, $redirect, $start, 'session-' . ++$this->signIns);

        self::assertTrue($result->isAdmitted());
        self::assertEquals($this->person, $result->linkedIdentity);

        return $result;
    }

    /**
     * Each violation of the result, as its setting and its code.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(ConnectionResult $result): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $result->violations);
    }
}
