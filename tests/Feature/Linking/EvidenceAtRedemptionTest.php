<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\EvidenceRules;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\Redemption\ReauthenticationBranch;
use SineMacula\Laravel\Sso\Handoffs\Redemption\SignInBranch;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Adversarial tests of how a redemption judges the provider's authentication
 * context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionEvidencePolicy::class)]
#[CoversClass(EvidenceRules::class)]
#[CoversClass(SignInBranch::class)]
#[CoversClass(ReauthenticationBranch::class)]
#[CoversClass(RedemptionResult::class)]
final class EvidenceAtRedemptionTest extends LinkingTestCase
{
    use CapturesLogs, DumpsValues;

    /** @var string A class a policy accepts. */
    private const string LOA2 = 'urn:example:loa:2';

    /** @var string Another class a policy accepts. */
    private const string LOA3 = 'urn:example:loa:3';

    /** @var string A class no policy here accepts, nothing else could spell. */
    private const string UNLISTED = 'urn:example:unlisted-class';

    /** @var string A method nothing else in an event or a log could spell. */
    private const string METHOD = 'retina';

    /** @var string The evidence's maximum age the tests set, in seconds. */
    private const string MAX_AGE_KEY = 'sso.linking.evidence_max_age_seconds';

    /** @var int The evidence's maximum age the tests set, in seconds. */
    private const int MAX_AGE = 600;

    /** @var int The clock skew the tests set, in seconds. */
    private const int SKEW = 30;

    /** @var string The `AuthnRequest` id a SAML flow is started with. */
    private const string SAML_REQUEST = '_request-evidence-1';

    /** @var string The `RelayState` a SAML flow is started with. */
    private const string SAML_RELAY = 'the-relay-state-of-the-evidence-request';

    /** @var string A SAML class of the fake provider's vocabulary. */
    private const string PPT = FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT;

    /** @var array<string, mixed> A policy accepting a password. */
    private const array PASSWORD = ['amr' => ['pwd'], 'combinations' => [['amr' => ['pwd']]]];

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var string The id of the active link of the subject. */
    private string $linkId;

    /**
     * Bind the package's policy, set the bounds apart from their defaults, and
     * link the subject, so each flow establishes an identity.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->bind(EvidencePolicy::class, ConnectionEvidencePolicy::class);

        config()->set(self::MAX_AGE_KEY, self::MAX_AGE);
        config()->set('sso.clock.skew_seconds', self::SKEW);

        app(LinkStore::class)->create(
            $this->connection,
            new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT),
            $this->person,
            LinkOrigin::PROVISIONING,
            Clients::browser(),
        );

        $this->linkId = Link::query()->sole()->id;

        $this->startRecordingEvents();
    }

    /**
     * Rows of `[policy, methods asserted, class asserted, methods answered or
     * null for none]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>, 2: ?string, 3: ?list<string>}>
     */
    public static function provideContexts(): iterable
    {
        $partial = ['amr' => ['pwd', 'otp'], 'combinations' => [['amr' => ['pwd']]]];
        $two     = ['amr' => ['pwd', 'otp'], 'combinations' => [['amr' => ['pwd', 'otp']]]];
        $class   = ['acr' => [self::LOA2], 'combinations' => [['acr' => self::LOA2]]];
        $pair    = ['amr' => ['pwd'], 'acr' => [self::LOA2], 'combinations' => [['amr' => ['pwd'], 'acr' => self::LOA2]]];
        $any     = ['amr' => ['pwd', 'otp'], 'acr' => [self::LOA2, self::LOA3], 'combinations' => [['amr' => ['otp']], ['acr' => self::LOA3]]];

        yield 'amr accepted' => [self::PASSWORD, ['pwd'], null, ['pwd']];
        yield 'amr unlisted' => [self::PASSWORD, ['otp'], null, null];
        yield 'amr partly listed: only the accepted enter' => [$partial, ['sms', 'pwd', 'custom', 'otp'], null, ['pwd', 'otp']];
        yield 'amr partly listed: in the order asserted' => [$partial, ['otp', 'sms', 'pwd'], null, ['otp', 'pwd']];
        yield 'amr stated twice enters once' => [$partial, ['pwd', 'pwd'], null, ['pwd']];
        yield 'amr accepted but not what counts' => [$partial, ['otp'], null, null];
        yield 'amr empty' => [self::PASSWORD, [], null, null];
        yield 'amr differing by case' => [self::PASSWORD, ['PWD'], null, null];
        yield 'two methods: exact' => [$two, ['pwd', 'otp'], null, ['pwd', 'otp']];
        yield 'two methods: one short' => [$two, ['pwd'], null, null];
        yield 'two methods: the other short' => [$two, ['otp'], null, null];
        yield 'two methods: one replaced by an unlisted one' => [$two, ['pwd', 'sms'], null, null];
        yield 'acr accepted' => [$class, [], self::LOA2, []];
        yield 'acr unlisted' => [$class, [], self::UNLISTED, null];
        yield 'acr absent' => [$class, [], null, null];
        yield 'acr differing by case' => [$class, [], strtoupper(self::LOA2), null];
        yield 'an unlisted acr is carried beside what counts' => [self::PASSWORD, ['pwd'], self::UNLISTED, ['pwd']];
        yield 'a method and a class: exact' => [$pair, ['pwd'], self::LOA2, ['pwd']];
        yield 'a method and a class: the method short' => [$pair, [], self::LOA2, null];
        yield 'a method and a class: the class short' => [$pair, ['pwd'], null, null];
        yield 'a method and a class: another class' => [$pair, ['pwd'], self::UNLISTED, null];
        yield 'any combination: the first' => [$any, ['otp'], null, ['otp']];
        yield 'any combination: the second' => [$any, ['pwd'], self::LOA3, ['pwd']];
        yield 'any combination: neither' => [$any, ['pwd'], self::LOA2, null];
    }

    /**
     * What each context comes to: the redemption goes on either way, with the
     * connection, the time and the raw class exactly when evidence is accepted.
     *
     * @param  array<string, mixed>  $policy
     * @param  list<string>  $methods
     * @param  ?string  $class
     * @param  ?list<string>  $expected
     * @return void
     */
    #[DataProvider('provideContexts')]
    public function testEachContextComesToItsEvidence(array $policy, array $methods, ?string $class, ?array $expected): void
    {
        $at     = $this->clock->now()->subMinute();
        $answer = $this->signIn($policy, new AuthenticationContext($at, $methods, $class));

        self::assertTrue($answer->isAdmitted());
        self::assertSame($this->person->id, $answer->linkedIdentity?->id);
        self::assertSame($this->linkId, $answer->linkId);

        if ($expected === null) {
            self::assertNull($answer->evidence);

            return;
        }

        self::assertSame($this->connection->id, $answer->evidence?->connectionId);
        self::assertSame($expected, $answer->evidence->methods());
        self::assertSame($class, $answer->evidence->rawContext());
        self::assertSame($at->toIso8601String(), $answer->evidence->authenticatedAt->toIso8601String());
    }

    /**
     * Rows of `[seconds from completion to authentication, seconds from
     * completion to redemption, accepted]`, under a 600-second maximum age and
     * 30 seconds of skew.
     *
     * @return iterable<string, array{0: int, 1: int, 2: bool}>
     */
    public static function provideTimes(): iterable
    {
        yield 'at the maximum age' => [-600, 0, true];
        yield 'one second under the maximum age' => [-599, 0, true];
        yield 'one second over the maximum age' => [-601, 0, false];
        yield 'at the maximum age when redeemed' => [-590, 10, true];
        yield 'one second under it when redeemed' => [-590, 9, true];
        yield 'one second over it when redeemed, though not when completed' => [-590, 11, false];
        yield 'at the skew' => [30, 0, true];
        yield 'one second under the skew' => [29, 0, true];
        yield 'one second past the skew' => [31, 0, false];
        yield 'past the skew when completed, but not when redeemed' => [31, 1, true];
        yield 'at the skew when redeemed' => [40, 10, true];
        yield 'one second past the skew when redeemed' => [40, 9, false];
    }

    /**
     * Each bound of the authentication time, measured at redemption.
     *
     * @param  int  $offset
     * @param  int  $advance
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideTimes')]
    public function testTheAuthenticationTimeIsMeasuredAtRedemption(int $offset, int $advance, bool $accepted): void
    {
        $this->connection->forceFill(['evidence_policy' => self::PASSWORD])->save();

        $start = $this->start();

        $this->verifying->claims = $this->linked(new AuthenticationContext($this->clock->now()->addSeconds($offset), ['pwd']));

        $completion = $this->complete();

        $this->clock->advance($advance);

        $answer = $this->admit($completion, $start);

        self::assertTrue($answer->isAdmitted());
        self::assertSame($accepted, $answer->evidence !== null);
    }

    /**
     * A microsecond past either bound is past it, the time carried at the full
     * precision the provider stated.
     *
     * @return void
     */
    public function testTheBoundsHoldToTheMicrosecond(): void
    {
        $oldest = $this->clock->now()->subSeconds(self::MAX_AGE);

        self::assertNull($this->signIn(self::PASSWORD, new AuthenticationContext($oldest->subMicroseconds(1), ['pwd']))->evidence);
        self::assertNotNull($this->signIn(self::PASSWORD, new AuthenticationContext($oldest->addMicroseconds(1), ['pwd']))->evidence);

        $latest = $this->clock->now()->addSeconds(self::SKEW);

        self::assertNull($this->signIn(self::PASSWORD, new AuthenticationContext($latest->addMicroseconds(1), ['pwd']))->evidence);
        self::assertNotNull($this->signIn(self::PASSWORD, new AuthenticationContext($latest->subMicroseconds(1), ['pwd']))->evidence);
    }

    /**
     * A code's short lifetime establishes nothing: one redeemed later than the
     * maximum age, though unexpired, is redeemed with no evidence.
     *
     * @return void
     */
    public function testACodeRedeemedLaterThanTheMaximumAgeHasNoEvidence(): void
    {
        config()->set(self::MAX_AGE_KEY, 60);
        config()->set('sso.applications.web.handoff_ttl_seconds', 300);

        $this->connection->forceFill(['evidence_policy' => self::PASSWORD])->save();

        $this->verifying->claims = $this->linked(new AuthenticationContext($this->clock->now(), ['pwd']));

        $firstStart  = $this->start();
        $first       = $this->complete();
        $secondStart = $this->start();
        $second      = $this->complete();
        $redeemedBy  = $this->clock->now()->addSeconds(61);

        self::assertTrue($second->handoff?->expiresAt->greaterThan($redeemedBy));

        $this->clock->advance(60);

        self::assertSame(['pwd'], $this->admit($first, $firstStart)->evidence?->methods());

        $this->clock->advance(1);

        $answer = $this->admit($second, $secondStart);

        self::assertTrue($answer->isAdmitted());
        self::assertNull($answer->evidence);
    }

    /**
     * No authentication time gives none, and the redemption goes on.
     *
     * @return void
     */
    public function testNoAuthenticationTimeGivesNoEvidence(): void
    {
        $answer = $this->signIn(self::PASSWORD, new AuthenticationContext(null, ['pwd']));

        self::assertTrue($answer->isAdmitted());
        self::assertNull($answer->evidence);
    }

    /**
     * The policy current at redemption decides, whichever way it moved since
     * the completion, and whatever the completion's was.
     *
     * @return void
     */
    public function testThePolicyCurrentAtRedemptionDecides(): void
    {
        $context = new AuthenticationContext($this->clock->now(), ['pwd']);
        $start   = $this->start();

        $this->connection->forceFill(['evidence_policy' => self::PASSWORD])->save();

        $this->verifying->claims = $this->linked($context);

        $completion = $this->complete();

        $this->connection->forceFill(['evidence_policy' => ['amr' => ['otp'], 'combinations' => [['amr' => ['otp']]]]])->save();

        self::assertNull($this->admit($completion, $start)->evidence);

        $start      = $this->start();
        $completion = $this->complete();

        $this->connection->forceFill(['evidence_policy' => self::PASSWORD])->save();

        self::assertSame(['pwd'], $this->admit($completion, $start)->evidence?->methods());
    }

    /**
     * Rows of `[what the column holds]`: none is a policy.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideStoredColumns(): iterable
    {
        yield 'SQL null' => [null];
        yield 'an empty list' => ['[]'];
        yield 'an empty map' => ['{}'];
        yield 'a number' => ['5'];
        yield 'a string' => ['"amr"'];
        yield 'the accepted list a string' => ['{"amr":"pwd","combinations":[{"amr":["pwd"]}]}'];
        yield 'no combinations' => ['{"amr":["pwd"]}'];
        yield 'a combination naming nothing' => ['{"amr":["pwd"],"combinations":[{}]}'];
        yield 'a combination not accepted' => ['{"amr":["pwd"],"combinations":[{"amr":["otp"]}]}'];
        yield 'an unknown name' => ['{"amr":["pwd"],"combinations":[{"amr":["pwd"]}],"other":true}'];
    }

    /**
     * A policy empty or malformed is insufficient: the redemption goes on with
     * none, and nothing throws.
     *
     * @param  ?string  $column
     * @return void
     */
    #[DataProvider('provideStoredColumns')]
    public function testAPolicyThatIsNoPolicyGivesNoEvidence(?string $column): void
    {
        DB::connection(StorageConnection::name())->table(StorageConnection::table('connections.table'))->where('id', $this->connection->id)->update(['evidence_policy' => $column]);

        $start = $this->start();

        $this->verifying->claims = $this->linked(new AuthenticationContext($this->clock->now(), ['pwd']));

        $answer = $this->admit($this->complete(), $start);

        self::assertTrue($answer->isAdmitted());
        self::assertNull($answer->evidence);
    }

    /**
     * Rows of `[policy, class stated, seconds from now it was authenticated,
     * whether it is accepted]`: SAML's `AuthnContextClassRef`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: int, 3: bool}>
     */
    public static function provideSamlContexts(): iterable
    {
        $listed = ['authn_context_class_ref' => [self::PPT, self::LOA2], 'combinations' => [['authn_context_class_ref' => self::PPT]]];
        $both   = ['authn_context_class_ref' => [self::PPT, self::LOA2], 'combinations' => [['authn_context_class_ref' => self::LOA2], ['authn_context_class_ref' => self::PPT]]];

        yield 'accepted' => [$listed, self::PPT, -60, true];
        yield 'unlisted' => [$listed, self::UNLISTED, -60, false];
        yield 'listed, and not what counts' => [$listed, self::LOA2, -60, false];
        yield 'one of two that count' => [$both, self::PPT, -60, true];
        yield 'at the maximum age' => [$listed, self::PPT, -600, true];
        yield 'one second under the maximum age' => [$listed, self::PPT, -599, true];
        yield 'one second over the maximum age' => [$listed, self::PPT, -601, false];
        yield 'at the skew' => [$listed, self::PPT, 30, true];
        yield 'an empty policy' => [[], self::PPT, -60, false];
        yield 'another protocol\'s names' => [self::PASSWORD, self::PPT, -60, false];
    }

    /**
     * A signed SAML response through the assertion consumer service and the
     * redemption: the class is carried as data, and no method is ever answered.
     *
     * @param  array<string, mixed>  $policy
     * @param  string  $class
     * @param  int  $offset
     * @param  bool  $accepted
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideSamlContexts')]
    public function testASamlResultComesToItsEvidence(array $policy, string $class, int $offset, bool $accepted): void
    {
        [$connection, $answer] = $this->samlSignIn($policy, $class, $offset);

        self::assertTrue($answer->isAdmitted());
        self::assertSame($this->person->id, $answer->linkedIdentity?->id);

        if (!$accepted) {
            self::assertNull($answer->evidence);

            return;
        }

        self::assertSame($connection->id, $answer->evidence?->connectionId);
        self::assertSame([], $answer->evidence->methods());
        self::assertSame($class, $answer->evidence->rawContext());
        self::assertSame($this->clock->now()->addSeconds($offset)->toIso8601String(), $answer->evidence->authenticatedAt->toIso8601String());
    }

    /**
     * A `link` is never asked: not when it creates a link, not when it finds
     * one, and it answers no evidence.
     *
     * @return void
     */
    public function testALinkIsNeverAsked(): void
    {
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $asked = [];

        $this->answering(static function () use (&$asked): ?AcceptedEvidence {
            $asked[] = true;

            return null;
        });

        $this->verifying->claims = $this->linked(new AuthenticationContext($this->clock->now(), ['pwd']));

        $start  = $this->start(Purpose::LINK, $this->person);
        $answer = $this->admit($this->complete(), $start, Purpose::LINK, $this->person);

        self::assertTrue($answer->isRedeemed());
        self::assertNull($answer->evidence);

        Link::query()->delete();

        $start  = $this->start(Purpose::LINK, $this->person);
        $answer = $this->admit($this->complete(), $start, Purpose::LINK, $this->person);

        self::assertTrue($answer->isRedeemed());
        self::assertSame(LinkOrigin::LINK_PURPOSE, Link::query()->sole()->provenance);
        self::assertNull($answer->evidence);
        self::assertSame([], $asked);
    }

    /**
     * A `sign_in` asks once, inside the transaction, with the result as it was
     * verified, the connection as locked, and the instant of the redemption.
     *
     * @return void
     */
    public function testASignInAsksOnceAtRedemption(): void
    {
        $this->connection->forceFill(['evidence_policy' => self::PASSWORD])->save();

        $accepted = new AcceptedEvidence($this->connection->id, $this->clock->now(), ['pwd']);
        $asked    = [];

        $this->answering(function (mixed $result, mixed $connection, mixed $now) use (&$asked, $accepted): AcceptedEvidence {
            self::assertInstanceOf(VerifiedResult::class, $result);
            self::assertInstanceOf(SsoConnection::class, $connection);
            self::assertInstanceOf(CarbonImmutable::class, $now);

            $asked[] = [
                $result->purpose,
                $result->authenticationContext->methods,
                $connection->getConnectionId(),
                SettingRules::isSame($connection->getEvidencePolicy(), self::PASSWORD),
                $now->toIso8601String(),
                DB::connection(StorageConnection::name())->transactionLevel() > 0,
            ];

            return $accepted;
        });

        $start = $this->start();

        $this->verifying->claims = $this->linked(new AuthenticationContext($this->clock->now(), ['pwd']));

        $completion = $this->complete();

        $this->clock->advance(5);

        $answer = $this->admit($completion, $start);

        self::assertSame([[Purpose::SIGN_IN, ['pwd'], $this->connection->id, true, $this->clock->now()->toIso8601String(), true]], $asked);
        self::assertSame($accepted, $answer->evidence);
    }

    /**
     * A reservation is activated first, so the evidence is of the identity it
     * just established; that identity and its link are answered with it.
     *
     * @return void
     */
    public function testAReservationAsksOnceActivated(): void
    {
        Link::query()->delete();

        $this->connection->forceFill(['evidence_policy' => self::PASSWORD])->save();

        $states = [];

        $policy = app(ConnectionEvidencePolicy::class);

        $this->answering(static function (mixed $result, mixed $connection, mixed $now) use (&$states, $policy): ?AcceptedEvidence {
            self::assertInstanceOf(VerifiedResult::class, $result);
            self::assertInstanceOf(SsoConnection::class, $connection);
            self::assertInstanceOf(CarbonImmutable::class, $now);

            $states[] = Link::query()->sole()->state;

            return $policy->evaluate($result, $connection, $now);
        });

        $start = $this->start();

        $this->verifying->claims = new VerifiedClaims(
            VerifyingDriver::ISSUER,
            VerifyingDriver::SUBJECT,
            null,
            ['mail' => self::EMAIL],
            new AuthenticationContext($this->clock->now(), ['pwd']),
            new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN),
        );

        $completion = $this->complete();

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

        $answer = $this->admit($completion, $start);

        self::assertSame([LinkState::ACTIVE], $states);
        self::assertSame(Link::query()->sole()->id, $answer->linkId);
        self::assertSame($this->person->id, $answer->linkedIdentity?->id);
        self::assertSame(['pwd'], $answer->evidence?->methods());
    }

    /**
     * An unlinked handoff establishes no identity, so it never asks.
     *
     * @return void
     */
    public function testAnUnlinkedHandoffIsNeverAsked(): void
    {
        Link::query()->delete();

        config()->set('sso.applications.web.unlinked_handoffs', true);

        $this->matcher->match = LinkEmailMatch::none();

        $asked = 0;

        $this->answering(static function () use (&$asked): ?AcceptedEvidence {
            $asked++;

            return null;
        });

        $start  = $this->start();
        $answer = $this->admit($this->complete(), $start);

        self::assertTrue($answer->isAdmitted());
        self::assertNull($answer->linkedIdentity);
        self::assertNull($answer->evidence);
        self::assertSame(0, $asked);
    }

    /**
     * A refusal never asks.
     *
     * @return void
     */
    public function testARefusalIsNeverAsked(): void
    {
        $asked = 0;

        $this->answering(static function () use (&$asked): ?AcceptedEvidence {
            $asked++;

            return null;
        });

        $start      = $this->start();
        $completion = $this->complete();

        Link::query()->delete();

        self::assertSame(FailureReason::LINK_CHANGED, $this->admit($completion, $start)->reason);
        self::assertSame(0, $asked);
    }

    /**
     * A `reauthenticate` carries what this authentication gave, renews with it,
     * and asks once, once the link and the session are judged.
     *
     * @return void
     */
    public function testAReauthenticationCarriesItsOwnEvidence(): void
    {
        $sessions = new RecordingSessions($this->linkId);
        $at       = $this->clock->now()->subSeconds(10);

        $this->app?->instance(ReauthenticationSessions::class, $sessions);
        $this->connection->forceFill(['evidence_policy' => self::PASSWORD])->save();

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, 'session-1');

        $this->verifying->claims = $this->linked(new AuthenticationContext($at, ['pwd', 'sms'], self::UNLISTED));

        $answer = $this->admit($this->complete(), $start, Purpose::REAUTHENTICATE);

        self::assertTrue($answer->isAdmitted());
        self::assertSame(['pwd'], $answer->evidence?->methods());
        self::assertSame(self::UNLISTED, $answer->evidence->rawContext());
        self::assertSame($this->connection->id, $answer->evidence->connectionId);
        self::assertSame($at->toIso8601String(), $answer->evidence->authenticatedAt->toIso8601String());
        self::assertCount(1, $sessions->renewed);
        self::assertSame('session-1', $sessions->renewed[0][0]);
        self::assertSame($at->toIso8601String(), $sessions->renewed[0][1]->toIso8601String());
        self::assertSame($answer->evidence, $sessions->renewed[0][2]);
    }

    /**
     * A `reauthenticate` with insufficient evidence still renews, offering
     * nothing.
     *
     * @return void
     */
    public function testAReauthenticationWithNoEvidenceStillRenews(): void
    {
        $sessions = new RecordingSessions($this->linkId);
        $at       = $this->clock->now();

        config()->set(self::MAX_AGE_KEY, 60);
        config()->set('sso.applications.web.handoff_ttl_seconds', 300);

        $this->app?->instance(ReauthenticationSessions::class, $sessions);
        $this->connection->forceFill(['evidence_policy' => self::PASSWORD])->save();

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, 'session-1');

        $this->verifying->claims = $this->linked(new AuthenticationContext($at, ['pwd']));

        $completion = $this->complete();

        $this->clock->advance(61);

        $answer = $this->admit($completion, $start, Purpose::REAUTHENTICATE);

        self::assertTrue($answer->isAdmitted());
        self::assertNull($answer->evidence);
        self::assertCount(1, $sessions->renewed);
        self::assertSame($at->toIso8601String(), $sessions->renewed[0][1]->toIso8601String());
        self::assertNull($sessions->renewed[0][2]);
    }

    /**
     * A contract's error rolls the redemption back with the code unconsumed, so
     * the caller retries its whole transaction, and shows no value.
     *
     * @return void
     */
    public function testAnErrorRollsTheRedemptionBackAndShowsNoValue(): void
    {
        $this->connection->forceFill(['evidence_policy' => ['amr' => [self::METHOD], 'combinations' => [['amr' => [self::METHOD]]]]])->save();

        $policy = app(ConnectionEvidencePolicy::class);
        $asked  = 0;

        $this->answering(static function (mixed $result, mixed $connection, mixed $now) use (&$asked, $policy): ?AcceptedEvidence {
            self::assertInstanceOf(VerifiedResult::class, $result);
            self::assertInstanceOf(SsoConnection::class, $connection);
            self::assertInstanceOf(CarbonImmutable::class, $now);

            if ($asked++ === 0) {
                throw new \RuntimeException('The contract failed.');
            }

            return $policy->evaluate($result, $connection, $now);
        });

        $start = $this->start();

        $this->verifying->claims = $this->linked(new AuthenticationContext($this->clock->now(), [self::METHOD], self::UNLISTED));

        $completion = $this->complete();

        try {
            $this->admit($completion, $start);
            self::fail('The error did not propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The contract failed.', $exception->getMessage());
            self::assertStringNotContainsString(self::METHOD, $exception->getTraceAsString());
            self::assertStringNotContainsString(self::UNLISTED, $exception->getTraceAsString());
        }

        self::assertSame([self::METHOD], $this->admit($completion, $start)->evidence?->methods());
        self::assertSame(2, $asked);
    }

    /**
     * Evidence adds no event: whether accepted or not, a `sign_in` reports the
     * same sequence.
     *
     * @return void
     */
    public function testASignInReportsNoMoreForItsEvidence(): void
    {
        $sequence = [AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class, HandoffRedeemed::class];

        self::assertNotNull($this->signIn(self::PASSWORD, new AuthenticationContext($this->clock->now(), ['pwd']))->evidence);

        $this->assertEventSequence($sequence);
        $this->assertNoFailure();

        $this->startRecordingEvents();

        self::assertNull($this->signIn(self::PASSWORD, new AuthenticationContext($this->clock->now(), ['otp']))->evidence);

        $this->assertEventSequence($sequence);
        $this->assertNoFailure();
    }

    /**
     * Evidence adds no event to a `reauthenticate` either.
     *
     * @return void
     */
    public function testAReauthenticationReportsNoMoreForItsEvidence(): void
    {
        $this->app?->instance(ReauthenticationSessions::class, new RecordingSessions($this->linkId));
        $this->connection->forceFill(['evidence_policy' => self::PASSWORD])->save();

        $start = $this->start(Purpose::REAUTHENTICATE, $this->person, 'session-1');

        $this->verifying->claims = $this->linked(new AuthenticationContext($this->clock->now(), ['pwd']));

        self::assertNotNull($this->admit($this->complete(), $start, Purpose::REAUTHENTICATE)->evidence);

        $this->assertEventSequence([AuthorizationRequestStarted::class, ResultVerified::class, HandoffIssued::class, HandoffRedeemed::class, ReauthenticationCompleted::class]);
    }

    /**
     * No evidence value is shown anywhere, and the answer refuses to be
     * serialised.
     *
     * @return void
     */
    public function testNoEvidenceValueReachesWhatMayBeShown(): void
    {
        $this->captureLogs();

        $policy = ['amr' => [self::METHOD], 'acr' => [self::UNLISTED], 'combinations' => [['amr' => [self::METHOD], 'acr' => self::UNLISTED]]];
        $answer = $this->signIn($policy, new AuthenticationContext($this->clock->now(), [self::METHOD], self::UNLISTED));

        self::assertSame([self::METHOD], $answer->evidence?->methods());

        $shown = [
            json_encode($this->capturedLogRecords()),
            json_encode($answer),
            print_r($answer, true),
            json_encode($answer->evidence),
            ...array_values(self::dumps($answer->evidence)),
        ];

        foreach ($this->recordedEvents() as $event) {
            array_push($shown, json_encode($event), ...array_values(self::dumps($event)));
        }

        foreach ($shown as $text) {
            self::assertStringNotContainsString(self::METHOD, (string) $text);
            self::assertStringNotContainsString(self::UNLISTED, (string) $text);
        }

        $this->expectExceptionObject(new \LogicException('A redemption result cannot be serialised.'));

        serialize($answer);
    }

    /**
     * Sign in through the connection under the policy, with the context.
     *
     * @param  array<string, mixed>  $policy
     * @param  \SineMacula\Laravel\Sso\Results\AuthenticationContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function signIn(array $policy, AuthenticationContext $context): RedemptionResult
    {
        $this->connection->forceFill(['evidence_policy' => $policy])->save();

        $start = $this->start();

        $this->verifying->claims = $this->linked($context);

        return $this->admit($this->complete(), $start);
    }

    /**
     * What the driver verifies of the linked subject, with the context.
     *
     * @param  \SineMacula\Laravel\Sso\Results\AuthenticationContext  $context
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    private function linked(AuthenticationContext $context): VerifiedClaims
    {
        return new VerifiedClaims(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT, null, ['mail' => self::EMAIL], $context);
    }

    /**
     * Bind a policy that answers through the closure.
     *
     * @param  \Closure(mixed, mixed, mixed): ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $answer
     * @return void
     */
    private function answering(\Closure $answer): void
    {
        $this->app?->instance(EvidencePolicy::class, new readonly class ($answer) implements EvidencePolicy {
            /**
             * Constructor.
             *
             * @param  \Closure(mixed, mixed, mixed): ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $answer
             */
            public function __construct(

                /** What answers. */
                private \Closure $answer,
            ) {}

            /**
             * Answer through the closure.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  \Carbon\CarbonImmutable  $now
             * @return ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence
             */
            #[\Override]
            public function evaluate(VerifiedResult $result, SsoConnection $connection, CarbonImmutable $now): ?AcceptedEvidence
            {
                return ($this->answer)($result, $connection, $now);
            }
        });
    }

    /**
     * Sign in through a SAML connection whose provider states the class at the
     * given offset, then redeem.
     *
     * @param  array<string, mixed>  $policy
     * @param  string  $class
     * @param  int  $offset
     * @return array{0: \SineMacula\Laravel\Sso\Models\Connection, 1: \SineMacula\Laravel\Sso\Handoffs\RedemptionResult}
     *
     * @throws \Random\RandomException
     */
    private function samlSignIn(array $policy, string $class, int $offset): array
    {
        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $connection = $this->samlConnection($policy);
        $verifier   = Verifier::generate();

        $this->makeAuthorizationRequest($connection, [
            'saml_request_id'   => self::SAML_REQUEST,
            'state_digest'      => hash('sha256', self::SAML_RELAY),
            'handoff_challenge' => $verifier->challenge()->value,
        ]);

        $response   = $this->samlResponse($connection, $class, $offset);
        $completion = app(CompletionService::class)->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $connection->id,
            $response->completionRequest(self::SAML_RELAY),
            Clients::browser(),
        );

        self::assertTrue($completion->isCompleted());

        return [$connection, $this->admitThrough($connection, $completion, $verifier)];
    }

    /**
     * A SAML connection trusting the fake provider, holding the policy, with
     * the provider's subject linked.
     *
     * @param  array<string, mixed>  $policy
     * @return \SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private function samlConnection(array $policy): Connection
    {
        $connection = $this->makeConnection([
            'protocol'          => 'saml2',
            'enabled'           => true,
            'settings'          => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
            'attribute_mapping' => ['email' => 'email'],
            'evidence_policy'   => $policy === [] ? null : $policy,
        ]);

        $certificate = self::idp()->certificate();
        $details     = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();

        $format  = FakeSamlResponse::PERSISTENT;
        $subject = 'v1|7:name_id|52:' . $format . '|-|-|5:alice';

        app(LinkStore::class)->create(
            $connection,
            new LinkSubject(FakeSamlIdentityProvider::ENTITY_ID, $subject, $format),
            $this->person,
            LinkOrigin::PROVISIONING,
            Clients::browser(),
        );

        return $connection;
    }

    /**
     * A valid response from the fake provider to the connection's service
     * provider, answering the request, with one statement of the class.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $class
     * @param  int  $offset
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function samlResponse(Connection $connection, string $class, int $offset): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($connection);
        $now       = $this->clock->now();
        $statement = [
            'instant'                 => $now->addSeconds($offset),
            'session_index'           => '_session-1',
            'session_not_on_or_after' => $now->addHours(8),
            'class'                   => $class,
        ];

        return self::idp()
            ->response($endpoints->entityId, $endpoints->assertionConsumerService, $now)
            ->with(['authn_statements' => [$statement]])
            ->inResponseTo(self::SAML_REQUEST);
    }

    /**
     * Redeem the completion's code through the connection, in a transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\Verifier  $verifier
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admitThrough(Connection $connection, CompletionResult $completion, Verifier $verifier): RedemptionResult
    {
        $code = (string) $completion->handoff?->code->reveal();

        return $connection->getConnection()->transaction(
            static fn (): RedemptionResult => app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $connection->id, $code, $verifier->reveal(), Clients::browser()),
        );
    }

    /**
     * The trusted identity provider, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
