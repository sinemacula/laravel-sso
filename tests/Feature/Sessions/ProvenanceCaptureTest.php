<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Admission;
use SineMacula\Laravel\Sso\Handoffs\Redemption\SignInBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\AuthenticationContext as ProviderContext;
use SineMacula\Laravel\Sso\Results\Enums\DeadlineEffect;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * The session provenance a redemption captures (SSO-9.7, SSO-9.10), through the
 * public flow from start to `admit()` over the package's link store: an
 * admitted `sign_in` captures the connection, its tenant, the protocol, the
 * provider's time, only the evidence accepted at redemption, the exact link and
 * its provenance as the locked admission found it (an activated reservation's
 * `verified_domain`, or an existing link's own), both deadlines and the version
 * of the enforcement judged under the redemption's locks; an unlinked sign-in
 * captures no link; a refusal, a `link` and a `reauthenticate` capture nothing,
 * so a later confirming link or a re-authentication never rewrites what was
 * captured; and the stored form survives a database's JSON column and projects
 * to the same `sso.*` keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Provenance::class)]
#[CoversClass(AuthenticationContext::class)]
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(RedemptionResult::class)]
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(SignInBranch::class)]
#[CoversClass(ReservationActivation::class)]
#[CoversClass(Admission::class)]
#[CoversClass(LinkResolution::class)]
#[CoversClass(LinkStore::class)]
final class ProvenanceCaptureTest extends LinkingTestCase
{
    /** @var string The table the test keeps a session's stored provenance in, as an adapter would. */
    private const string SESSIONS = 'provenance_capture_test_sessions';

    /** @var string The session a `reauthenticate` flow is started on. */
    private const string SESSION = 'session-1';

    /** @var string When the driver says the provider authenticated the person. */
    private const string AUTHENTICATED = '2026-11-01T09:30:00.000000Z';

    /**
     * Bind a fresh caller and an eligibility that lets every identity link,
     * which a `link` flow needs, and create the sessions table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);

        DB::connection(StorageConnection::name())->getSchemaBuilder()->create(self::SESSIONS, static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->json('provenance');
        });
    }

    /**
     * Drop the sessions table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::connection(StorageConnection::name())->getSchemaBuilder()->dropIfExists(self::SESSIONS);

        parent::tearDown();
    }

    /**
     * A sign-in whose verified domain reservation is activated at redemption
     * captures that link, as `verified_domain`, with every other fact, and
     * projects it under the `sso.*` keys.
     *
     * @return void
     */
    public function testADomainLinkActivatedAtSignInIsCapturedAsAdmitted(): void
    {
        $answer = $this->signIn();
        $link   = Link::query()->sole();

        self::assertTrue($answer->isAdmitted());
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $link->provenance);
        self::assertSame([
            'version'                          => 1,
            'connection_id'                    => $this->connection->id,
            'tenant_id'                        => 'tenant-1',
            'protocol'                         => VerifyingDriver::NAME,
            'provider_auth_time'               => self::AUTHENTICATED,
            'provider_amr'                     => [],
            'provider_acr'                     => null,
            'provider_authn_context_class_ref' => null,
            'link_id'                          => $link->id,
            'link_provenance'                  => 'verified_domain',
            'provider_session_deadline'        => null,
            'session_not_after'                => null,
            'enforcement_version'              => null,
        ], $answer->provenance?->toArray());
        self::assertSame($answer->linkId, $answer->provenance->linkId);

        $context = AuthenticationContext::of($answer->provenance);

        self::assertSame(
            [$this->connection->id, 'tenant-1', VerifyingDriver::NAME, $link->id, 'verified_domain'],
            [$context['sso.connection'], $context['sso.tenant'], $context['sso.protocol'], $context['sso.link'], $context['sso.link_provenance']],
        );
    }

    /**
     * Each provenance an existing link can hold.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin}>
     */
    public static function origins(): iterable
    {
        foreach (LinkOrigin::cases() as $origin) {
            yield $origin->value => [$origin];
        }
    }

    /**
     * A sign-in through an existing link captures that exact link with the
     * provenance it held under the redemption's locks.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return void
     */
    #[DataProvider('origins')]
    public function testAnExistingLinkIsCapturedWithItsOwnProvenance(LinkOrigin $origin): void
    {
        $held   = $this->hold($origin);
        $answer = $this->signIn();

        self::assertTrue($answer->isAdmitted());
        self::assertSame([$held->id, $origin], [$answer->provenance?->linkId, $answer->provenance?->linkProvenance]);
        self::assertSame($origin->value, AuthenticationContext::of($answer->provenance)['sso.link_provenance']);
    }

    /**
     * A later confirming `link` turns the link's provenance to `link_purpose`
     * and answers no provenance, so there is nothing for the application to
     * write over what the earlier sign-in captured as `verified_domain`. Only a
     * new sign-in captures the link as it now is.
     *
     * @return void
     */
    public function testALaterConfirmingLinkNeverRewritesTheCapturedProvenance(): void
    {
        $first = $this->signIn();

        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $first->provenance?->linkProvenance);

        $start      = $this->start(Purpose::LINK, $this->person);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        $confirmed = $this->admit($completion, $start, Purpose::LINK, $this->person);

        self::assertTrue($confirmed->isRedeemed());
        self::assertNull($confirmed->provenance);
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);

        $again = $this->signIn();

        self::assertSame([$first->linkId, LinkOrigin::LINK_PURPOSE], [$again->provenance?->linkId, $again->provenance?->linkProvenance]);
    }

    /**
     * A re-authentication renews the session's time through its contract once
     * and answers no provenance, so there is nothing for the application to
     * write over how the session began, as the sign-in captured it.
     *
     * @return void
     */
    public function testAReauthenticationCapturesNothing(): void
    {
        $link     = $this->hold(LinkOrigin::PROVISIONING);
        $sessions = new RecordingSessions($link->id);

        $this->app?->instance(ReauthenticationSessions::class, $sessions);

        $signIn = $this->signIn();

        $this->clock->advance(60);

        $this->verifying->claims = $this->claimsWith(new ProviderContext($this->clock->now(), ['pwd']));

        $start      = $this->start(Purpose::REAUTHENTICATE, $this->person, self::SESSION);
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertTrue($answer->isAdmitted());
        self::assertNull($answer->provenance);
        self::assertSame(1, $sessions->renewals());

        self::assertSame(self::AUTHENTICATED, AuthenticationContext::of($signIn->provenance)['sso.provider_auth_time']);
    }

    /**
     * The evidence accepted at redemption is what is captured: its methods, and
     * its raw context as `acr`, as for every driver but `saml2`.
     *
     * @return void
     */
    public function testTheEvidenceAcceptedAtRedemptionIsCaptured(): void
    {
        $this->hold(LinkOrigin::PROVISIONING);
        $this->bindEvidence(new AcceptedEvidence($this->connection->id, $this->clock->now(), ['pwd', 'mfa'], 'urn:example:class'));

        $answer = $this->signIn();

        self::assertSame(
            [['pwd', 'mfa'], 'urn:example:class', null],
            [$answer->provenance?->providerMethods(), $answer->provenance?->providerAcr(), $answer->provenance?->providerAuthnContextClassRef()],
        );
    }

    /**
     * With no evidence accepted, what the provider asserted about how is not
     * captured: no methods and no raw context, though the assertion stated
     * both, and never the provider session's id; its time is. Its deadline,
     * which limits the session by default, is captured both raw and as the
     * effective cap.
     *
     * @return void
     */
    public function testWhatTheProviderAssertedIsNotCapturedUnlessAccepted(): void
    {
        $this->hold(LinkOrigin::PROVISIONING);

        $this->verifying->claims = $this->claimsWith();

        $answer = $this->signIn();
        $stored = $answer->provenance?->toArray();

        self::assertSame([[], null, null], [$answer->provenance?->providerMethods(), $answer->provenance?->providerAcr(), $answer->provenance?->providerAuthnContextClassRef()]);
        self::assertIsArray($stored);
        self::assertSame(self::AUTHENTICATED, $stored['provider_auth_time']);
        self::assertSame(['2026-11-01T17:30:00.000000Z', '2026-11-01T17:30:00.000000Z'], [$stored['provider_session_deadline'], $stored['session_not_after']]);
        self::assertStringNotContainsString('provider-session-7', (string) json_encode($stored));
        self::assertStringNotContainsString('urn:asserted:class', (string) json_encode($stored));
    }

    /**
     * A deadline the deadline contract ignores sets no cap, and its raw value
     * is still captured.
     *
     * @return void
     */
    public function testAnIgnoredDeadlineIsStillCapturedRaw(): void
    {
        $this->hold(LinkOrigin::PROVISIONING);

        $this->app?->instance(ProviderSessionDeadline::class, new readonly class implements ProviderSessionDeadline {
            /**
             * Ignore every deadline.
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

        $this->verifying->claims = $this->claimsWith();

        $answer = $this->signIn();
        $stored = $answer->provenance?->toArray();

        self::assertNull($answer->sessionNotAfter);
        self::assertIsArray($stored);
        self::assertArrayHasKey('session_not_after', $stored);
        self::assertSame(['2026-11-01T17:30:00.000000Z', null], [$stored['provider_session_deadline'], $stored['session_not_after']]);
    }

    /**
     * The enforcement version the sign-in carried is captured.
     *
     * @return void
     */
    public function testTheEnforcementVersionIsCaptured(): void
    {
        $this->hold(LinkOrigin::PROVISIONING);

        $this->app?->instance(Enforcement::class, new readonly class implements Enforcement {
            /**
             * Require nothing, at version `enforcement-7`.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
             */
            #[\Override]
            public function policy(string $tenantId, string $application): EnforcementPolicy
            {
                unset($application);

                return EnforcementPolicy::notRequired($tenantId, $tenantId, 'enforcement-7');
            }
        });

        $answer = $this->signIn();

        self::assertSame(['enforcement-7', 'enforcement-7'], [$answer->enforcementVersion, $answer->provenance?->enforcementVersion]);
    }

    /**
     * A rule that changed between the completion and the redemption: the
     * session keeps the version the redemption judged under its locks, never
     * the one the completion checked, which the code does not carry.
     *
     * @return void
     */
    public function testTheSessionKeepsTheVersionReadUnderTheRedemptionsLock(): void
    {
        $this->hold(LinkOrigin::PROVISIONING);

        $rule = new class implements Enforcement {
            /** @var string The version the rule is at now. */
            public string $version = 'enforcement-7';

            /**
             * Require nothing, at the version the rule is at now.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
             */
            #[\Override]
            public function policy(string $tenantId, string $application): EnforcementPolicy
            {
                unset($application);

                return EnforcementPolicy::notRequired($tenantId, $tenantId, $this->version);
            }
        };

        $this->app?->instance(Enforcement::class, $rule);

        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());
        self::assertArrayNotHasKey('enforcement_version', HandoffCode::query()->sole()->getAttributes());

        $rule->version = 'enforcement-8';

        $answer = $this->admit($completion, $start);

        self::assertTrue($answer->isRedeemed());
        self::assertSame(['enforcement-8', 'enforcement-8'], [$answer->enforcementVersion, $answer->provenance?->enforcementVersion]);
        self::assertSame('enforcement-8', AuthenticationContext::of($answer->provenance)[AuthenticationContext::ENFORCEMENT_VERSION]);
    }

    /**
     * An unlinked sign-in is captured with no link and no link provenance.
     *
     * @return void
     */
    public function testAnUnlinkedSignInIsCapturedWithNoLink(): void
    {
        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->matcher->match = LinkEmailMatch::none();

        $answer = $this->signIn();

        self::assertTrue($answer->isAdmitted());
        self::assertNull($answer->linkedIdentity);
        self::assertSame([$this->connection->id, null, null], [$answer->provenance?->connectionId, $answer->provenance?->linkId, $answer->provenance?->linkProvenance]);
    }

    /**
     * A refused redemption captures nothing.
     *
     * @return void
     */
    public function testARefusalCapturesNothing(): void
    {
        $this->hold(LinkOrigin::PROVISIONING);

        $start      = $this->start();
        $completion = $this->complete();

        Link::query()->delete();

        $answer = $this->admit($completion, $start);

        self::assertSame(FailureReason::LINK_CHANGED, $answer->reason);
        self::assertNull($answer->provenance);
    }

    /**
     * The stored form survives a database's JSON column, which may give its
     * keys back in another order, and projects as the provenance captured.
     *
     * @return void
     */
    public function testTheStoredFormSurvivesAJsonColumn(): void
    {
        $this->hold(LinkOrigin::PROVISIONING);
        $this->bindEvidence(new AcceptedEvidence($this->connection->id, $this->clock->now(), ['pwd']));

        $this->verifying->claims = $this->claimsWith();

        $answer = $this->signIn();

        $this->keep(self::SESSION, $answer);

        self::assertSame($answer->provenance?->toArray(), Provenance::restore($this->kept(self::SESSION))->toArray());
        self::assertSame(AuthenticationContext::of($answer->provenance), AuthenticationContext::fromStored($this->kept(self::SESSION)));
    }

    /**
     * Start, complete and admit a `sign_in`.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function signIn(): RedemptionResult
    {
        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());

        return $this->admit($completion, $start);
    }

    /**
     * Make the subject's active link for the person, with the provenance.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function hold(LinkOrigin $origin): Link
    {
        $creation = app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT), $this->person, $origin);

        self::assertTrue($creation->isCreated());

        return Link::query()->whereKey($creation->linkId())->sole();
    }

    /**
     * Bind an evidence contract that accepts what is given.
     *
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $accepted
     * @return void
     */
    private function bindEvidence(?AcceptedEvidence $accepted): void
    {
        $this->app?->instance(EvidencePolicy::class, new readonly class ($accepted) implements EvidencePolicy {
            /**
             * Constructor.
             *
             * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $accepted
             */
            public function __construct(

                /** What it accepts. */
                private ?AcceptedEvidence $accepted,
            ) {}

            /**
             * Accept what it was given.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \Carbon\CarbonImmutable  $now
             * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
             */
            #[\Override]
            public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
            {
                unset($result, $connection, $now);

                return $this->accepted;
            }
        });
    }

    /**
     * What the driver verifies: the subject with the linking email, and the
     * authentication context given, or by default one asserting every part (the
     * time now, methods, a context class, a provider session and a deadline at
     * 17:30).
     *
     * @param  ?\SineMacula\Laravel\Sso\Results\AuthenticationContext  $context
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    private function claimsWith(?ProviderContext $context = null): VerifiedClaims
    {
        $deadline = CarbonImmutable::parse('2026-11-01T17:30:00Z');
        $asserted = $context ?? new ProviderContext($this->clock->now(), ['pwd', 'otp', 'hwk'], 'urn:asserted:class', 'provider-session-7', $deadline);

        return new VerifiedClaims(
            VerifyingDriver::ISSUER,
            VerifyingDriver::SUBJECT,
            null,
            ['mail' => self::EMAIL],
            $asserted,
            new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN),
        );
    }

    /**
     * Keep the redemption's captured provenance for the session, as an adapter
     * writes it once with the session, in a JSON column.
     *
     * @param  string  $session
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $answer
     * @return void
     */
    private function keep(string $session, RedemptionResult $answer): void
    {
        self::assertNotNull($answer->provenance);

        DB::connection(StorageConnection::name())->table(self::SESSIONS)->insert(['id' => $session, 'provenance' => json_encode($answer->provenance->toArray())]);
    }

    /**
     * The provenance kept for the session, decoded.
     *
     * @param  string  $session
     * @return array<array-key, mixed>
     */
    private function kept(string $session): array
    {
        $stored = DB::connection(StorageConnection::name())->table(self::SESSIONS)->where('id', $session)->value('provenance');

        self::assertIsString($stored);

        return (array) json_decode($stored, true, flags: JSON_THROW_ON_ERROR);
    }
}
