<?php

declare(strict_types = 1);

namespace Tests\Feature\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsLockOrder;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Enforcement\ListedExemption;
use Tests\Fixtures\Enforcement\ScriptedInheritance;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Feature tests for redeeming a handoff code the package's own store issued
 * (SSO-9.2, SSO-9.9, SSO-4.3, SSO-4.6, SSO-8.5, SSO-5.2, SSO-11.3, SSO-11.5,
 * SSO-11.8, SSO-11.9): each step's reason in its order, a code failing several
 * checks reporting the first; a wrong purpose, application, connection or
 * verifier consuming the code, so a correct redemption after it is a replay;
 * the expiry at its second and either side; a voided code; a code the
 * single-use store has seen; a link removed, reassigned or added since
 * completion; enforcement turned on and a connection disabled since; the
 * completed-sign-in flag set by a linked `sign_in` alone; verifiers of 43 and
 * 128 characters and either side; codes, references and verifiers never
 * accepted as one another; a full limit; a corrupt stored result and a database
 * error that propagate; the locks taken in the package's order (the tenant's
 * enforcement row, then the connections in ascending id order, then the code)
 * with the feature on, the connection and the code alone with it off, with no
 * enforcement statement and no inheritance asked; a code that no longer names
 * the connection or application its locks were taken for; a connection gone
 * before its lock; and an enforcing tenant that moved since the lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffRecheck::class)]
final class HandoffRedemptionTest extends TestCase
{
    use RecordsLockOrder, UsesConnections, UsesEnforcement;

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The S256 challenge of the client's verifier. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var string A well-formed verifier that is not the client's. */
    private const string WRONG_VERIFIER = 'another-clients-verifier-of-43-characters-0';

    /** @var string The request's public reference every code carries. */
    private const string REFERENCE = 'Cq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection the codes are issued through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\Connection Another usable connection of the tenant. */
    private Connection $other;

    /** @var ?\SineMacula\Laravel\Sso\Identities\IdentityReference What every result is linked to, at issuance and as the linker answers now. */
    private ?IdentityReference $linked = null;

    /** @var list<\SineMacula\Laravel\Sso\Results\VerifiedResult> Every result the linker was asked about. */
    private array $linkerAsked = [];

    /**
     * Bind a fixed clock, a linker answering the linked identity and a request
     * from an IP address, register the driver, and create the tables and two
     * usable connections.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock  = new FixedClock('2026-11-01T09:30:00Z');
        $this->linked = new IdentityReference('App\Models\User', '42');

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance('request', Request::create('/auth/sso/handoffs', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));
        $this->app?->instance(Linker::class, self::linker(function (VerifiedResult $result): ?IdentityReference {
            $this->linkerAsked[] = $result;

            return $this->linked;
        }));

        $driver = new VerifyingDriver;

        config()->set('sso.features.oidc', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
        $this->other      = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
    }

    /**
     * A `sign_in` code redeemed with its purpose, application, connection and
     * verifier answers the result and everything it was bound to, with the
     * enforcement version read under the redemption's locks (none, with no rule
     * stored); it is consumed now, recorded in the single-use store by its
     * digest until its expiry, its connection's completed sign-in is
     * acknowledged, and the linker was asked once, with the result restored.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASignInCodeIsRedeemed(): void
    {
        $code = $this->issue();

        $this->clock->advance(5);

        $answer = $this->redeem($code);

        self::assertTrue($answer->isRedeemed());
        self::assertSame($this->verifiedResult()->toArray(), $answer->result?->toArray());
        self::assertSame(['type' => 'App\Models\User', 'id' => '42'], $answer->linkedIdentity?->jsonSerialize());
        self::assertNull($answer->identity);
        self::assertNull($answer->sessionId);
        self::assertNull($answer->enforcementVersion);
        self::assertSame('2026-11-01T18:00:00+00:00', $answer->sessionNotAfter?->toIso8601String());
        self::assertSame('2026-11-01T09:30:05+00:00', $this->stored($code)->redeemed_at?->toIso8601String());
        self::assertSame([[HandoffRedemption::NAMESPACE, hash('sha256', hash('sha256', $code)), '2026-11-01T09:31:00+00:00']], $this->singleUseKeys());
        self::assertSame('handoff_code', HandoffRedemption::NAMESPACE);
        self::assertTrue($this->reloaded($this->connection)->has_completed_sign_in);
        self::assertFalse($this->reloaded($this->other)->has_completed_sign_in);
        self::assertCount(1, $this->linkerAsked);
        self::assertSame($this->verifiedResult()->toArray(), $this->linkerAsked[0]->toArray());
    }

    /**
     * A `link` code answers the identity the flow was started for, and a
     * `reauthenticate` code that identity and its session; neither acknowledges
     * a completed sign-in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testALinkAndAReauthenticateCodeAnswerTheirIdentityAndSession(): void
    {
        $this->readyForTheFlowsIdentity();

        $link           = $this->redeem($this->issue(Purpose::LINK), purpose: Purpose::LINK);
        $reauthenticate = $this->redeem($this->issue(Purpose::REAUTHENTICATE), purpose: Purpose::REAUTHENTICATE);

        self::assertTrue($link->isRedeemed());
        self::assertSame('link', $link->result?->purpose->value);
        self::assertSame(['type' => 'App\Models\User', 'id' => '7'], $link->identity?->jsonSerialize());
        self::assertSame(['type' => 'App\Models\User', 'id' => '7'], $link->linkedIdentity?->jsonSerialize());
        self::assertSame('link-7', $link->linkId);
        self::assertNull($link->sessionId);

        self::assertTrue($reauthenticate->isRedeemed());
        self::assertSame('reauthenticate', $reauthenticate->result?->purpose->value);
        self::assertSame(['type' => 'App\Models\User', 'id' => '7'], $reauthenticate->identity?->jsonSerialize());
        self::assertSame('session-1', $reauthenticate->sessionId);

        self::assertFalse($this->reloaded($this->connection)->has_completed_sign_in);
    }

    /**
     * A code failing several checks is refused for the first of them, in the
     * order the redemption makes them: the connection's row, a voided code, a
     * replay, the expiry, the purpose, the application, the connection, the
     * verifier, then the recheck.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeFailingSeveralChecksIsRefusedForTheFirst(): void
    {
        $wrong = fn (string $code): RedemptionResult => $this->redeem($code, self::WRONG_VERIFIER, Purpose::LINK, 'mobile', $this->other->id);

        $gone = $this->issue();
        $this->stored($gone)->forceFill(['voided_at' => $this->clock->now(), 'connection_id' => '01jbz0000000000000000000zz'])->save();

        $voided = $this->issue(expiresAt: $this->clock->now());
        $this->stored($voided)->forceFill(['voided_at' => $this->clock->now(), 'redeemed_at' => $this->clock->now()])->save();

        $replayed = $this->issue(expiresAt: $this->clock->now());
        $this->stored($replayed)->forceFill(['redeemed_at' => $this->clock->now()])->save();

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $wrong($gone)->reason);
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $wrong($voided)->reason);
        self::assertSame(FailureReason::REPLAYED, $wrong($replayed)->reason);
        self::assertSame(FailureReason::HANDOFF_EXPIRED, $wrong($this->issue(expiresAt: $this->clock->now()))->reason);
        self::assertSame(FailureReason::PURPOSE_MISMATCH, $wrong($this->issue())->reason);
        self::assertSame(FailureReason::APPLICATION_MISMATCH, $this->redeem($this->issue(), self::WRONG_VERIFIER, application: 'mobile', connectionId: $this->other->id)->reason);
        self::assertSame(FailureReason::CONNECTION_MISMATCH, $this->redeem($this->issue(), self::WRONG_VERIFIER, connectionId: $this->other->id)->reason);

        $this->linked = new IdentityReference('App\Models\User', '43');

        $code = $this->issue();

        $this->connection->forceFill(['enabled' => false])->save();
        $this->linked = null;

        self::assertSame(FailureReason::VERIFIER_MISMATCH, $this->redeem($code, self::WRONG_VERIFIER)->reason);
        self::assertSame([], $this->linkerAsked);
    }

    /**
     * Each mismatch, with what is presented.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Events\Enums\FailureReason, 1: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 2: string, 3: string, 4: string}>
     */
    public static function mismatches(): iterable
    {
        yield 'a link redemption' => [FailureReason::PURPOSE_MISMATCH, Purpose::LINK, 'web', 'own', self::VERIFIER];
        yield 'a reauthenticate redemption' => [FailureReason::PURPOSE_MISMATCH, Purpose::REAUTHENTICATE, 'web', 'own', self::VERIFIER];
        yield 'another application' => [FailureReason::APPLICATION_MISMATCH, Purpose::SIGN_IN, 'mobile', 'own', self::VERIFIER];
        yield 'the application in another case' => [FailureReason::APPLICATION_MISMATCH, Purpose::SIGN_IN, 'Web', 'own', self::VERIFIER];
        yield 'another connection' => [FailureReason::CONNECTION_MISMATCH, Purpose::SIGN_IN, 'web', 'other', self::VERIFIER];
        yield 'the connection in upper case' => [FailureReason::CONNECTION_MISMATCH, Purpose::SIGN_IN, 'web', 'upper case', self::VERIFIER];
        yield 'another verifier' => [FailureReason::VERIFIER_MISMATCH, Purpose::SIGN_IN, 'web', 'own', self::WRONG_VERIFIER];
    }

    /**
     * A wrong purpose, application, connection or verifier consumes the code:
     * it is refused for that, and a correct redemption after it is a replay.
     * Each is compared exactly.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  string  $connection
     * @param  string  $verifier
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('mismatches')]
    public function testAMismatchConsumesTheCode(FailureReason $reason, Purpose $purpose, string $application, string $connection, string $verifier): void
    {
        $code = $this->issue();

        $connectionId = match ($connection) {
            'other'      => $this->other->id,
            'upper case' => strtoupper($this->connection->id),
            default      => $this->connection->id,
        };

        $refused = $this->redeem($code, $verifier, $purpose, $application, $connectionId);

        self::assertTrue($refused->isRefused());
        self::assertSame($reason, $refused->reason);
        self::assertNull($refused->result);
        self::assertSame('2026-11-01T09:30:00+00:00', $this->stored($code)->redeemed_at?->toIso8601String());
        self::assertCount(1, $this->singleUseKeys());

        self::assertSame(FailureReason::REPLAYED, $this->redeem($code)->reason);
        self::assertFalse($this->reloaded($this->connection)->has_completed_sign_in);
        self::assertSame([], $this->linkerAsked);
    }

    /**
     * Seconds since issuance, the reason, and until when the store keeps it.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason, 2: string}>
     */
    public static function expiries(): iterable
    {
        yield 'a second before its expiry' => [59, null, '2026-11-01T09:31:00+00:00'];
        yield 'at its expiry' => [60, FailureReason::HANDOFF_EXPIRED, '2026-11-01T09:31:01+00:00'];
        yield 'a second after its expiry' => [61, FailureReason::HANDOFF_EXPIRED, '2026-11-01T09:31:02+00:00'];
    }

    /**
     * A code is redeemed until a second before its expiry; at its expiry and
     * after it is `handoff_expired`, and consumed. The single-use store keeps
     * it until its expiry, and at least a second from now.
     *
     * @param  int  $elapsed
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $kept
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('expiries')]
    public function testTheExpiryBoundaries(int $elapsed, ?FailureReason $reason, string $kept): void
    {
        $code = $this->issue();

        $this->clock->advance($elapsed);

        $answer = $this->redeem($code);

        self::assertSame($reason, $answer->reason);
        self::assertSame($this->clock->now()->toIso8601String(), $this->stored($code)->redeemed_at?->toIso8601String());
        self::assertSame($kept, $this->singleUseKeys()[0][2]);
    }

    /**
     * A code a change to its connection voided is `handoff_unknown`, and is
     * neither consumed nor recorded.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAVoidedCodeIsUnknown(): void
    {
        $code = $this->issue();

        $this->stored($code)->forceFill(['voided_at' => $this->clock->now()])->save();

        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->redeem($code)->reason);
        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame([], $this->singleUseKeys());
        self::assertFalse($this->reloaded($this->connection)->has_completed_sign_in);
    }

    /**
     * A code redeemed before is `replayed`, and written nothing more.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedeemedCodeIsReplayed(): void
    {
        $code = $this->issue();

        self::assertTrue($this->redeem($code)->isRedeemed());

        $this->clock->advance(3);

        $replay = $this->redeem($code);

        self::assertTrue($replay->isRefused());
        self::assertSame(FailureReason::REPLAYED, $replay->reason);
        self::assertSame('2026-11-01T09:30:00+00:00', $this->stored($code)->redeemed_at?->toIso8601String());
        self::assertCount(1, $this->singleUseKeys());
    }

    /**
     * A code the single-use store has already seen is `replayed`, and is not
     * consumed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeTheSingleUseStoreHasSeenIsReplayed(): void
    {
        $code = $this->issue();

        app(SingleUseStore::class)->record(HandoffRedemption::NAMESPACE, hash('sha256', $code), $this->clock->now()->addMinute());

        self::assertSame(FailureReason::REPLAYED, $this->redeem($code)->reason);
        self::assertNull($this->stored($code)->redeemed_at);
        self::assertFalse($this->reloaded($this->connection)->has_completed_sign_in);
    }

    /**
     * How a link may have changed since completion.
     *
     * @return iterable<string, array{0: ?\SineMacula\Laravel\Sso\Identities\IdentityReference, 1: ?\SineMacula\Laravel\Sso\Identities\IdentityReference}>
     */
    public static function linkChanges(): iterable
    {
        $user = new IdentityReference('App\Models\User', '42');

        yield 'removed' => [$user, null];
        yield 'reassigned to another id' => [$user, new IdentityReference('App\Models\User', '43')];
        yield 'reassigned to another type' => [$user, new IdentityReference('App\Models\Admin', '42')];
        yield 'an id in another case' => [new IdentityReference('App\Models\User', 'ab'), new IdentityReference('App\Models\User', 'AB')];
        yield 'added' => [null, $user];
    }

    /**
     * A link removed, reassigned to another identity (by id or by type), or
     * added where there was none since completion is `link_changed`, and the
     * code stays consumed.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $atCompletion
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $now
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('linkChanges')]
    public function testALinkChangedSinceCompletionIsRefused(?IdentityReference $atCompletion, ?IdentityReference $now): void
    {
        $this->linked = $atCompletion;

        $code = $this->issue();

        $this->linked = $now;

        $answer = $this->redeem($code);

        self::assertSame(FailureReason::LINK_CHANGED, $answer->reason);
        self::assertNull($answer->result);
        self::assertNotNull($this->stored($code)->redeemed_at);
        self::assertSame(FailureReason::REPLAYED, $this->redeem($code)->reason);
        self::assertFalse($this->reloaded($this->connection)->has_completed_sign_in);
    }

    /**
     * An unlinked handoff whose result is still linked to nothing is redeemed,
     * with no linked identity, and acknowledges no sign-in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnUnlinkedHandoffIsRedeemedWithoutAcknowledgingASignIn(): void
    {
        $this->linked = null;

        $code   = $this->issue();
        $answer = $this->redeem($code);

        self::assertTrue($answer->isRedeemed());
        self::assertNull($answer->linkedIdentity);
        self::assertNotNull($this->stored($code)->redeemed_at);
        self::assertFalse($this->reloaded($this->connection)->has_completed_sign_in);
    }

    /**
     * Enforcement turned on since completion, by connections this one is not
     * among, is `enforcement_unsatisfied`; turned on including it, the code is
     * redeemed, answering the version of the rule read under the redemption's
     * locks.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEnforcementTurnedOnSinceCompletion(): void
    {
        config()->set('sso.features.enforcement', true);

        $code = $this->issue();

        $enforcement = $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$this->other->id]]);

        self::assertSame(FailureReason::ENFORCEMENT_UNSATISFIED, $this->redeem($code)->reason);
        self::assertNotNull($this->stored($code)->redeemed_at);
        self::assertFalse($this->reloaded($this->connection)->has_completed_sign_in);

        $enforcement->forceFill(['connection_ids' => [$this->other->id, $this->connection->id]])->save();

        $kept   = $this->issue();
        $answer = $this->redeem($kept);

        self::assertTrue($answer->isRedeemed());
        self::assertNotNull($answer->enforcementVersion);
        self::assertSame(TenantEnforcement::query()->sole()->version, $answer->enforcementVersion);
    }

    /**
     * The redemption never asks the exemption contract: an identity it would
     * exempt is still refused `enforcement_unsatisfied` through a connection
     * the rule does not list, and the contract is never asked. Only the
     * adapter's gate asks it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheRedemptionNeverAsksTheExemptionContract(): void
    {
        config()->set('sso.features.enforcement', true);

        $exemption = new ListedExemption([new IdentityReference('App\Models\User', '42')]);

        $this->app?->instance(EnforcementExemption::class, $exemption);

        $code = $this->issue();

        $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$this->other->id]]);

        self::assertSame(FailureReason::ENFORCEMENT_UNSATISFIED, $this->redeem($code)->reason);
        self::assertSame([], $exemption->asked());
    }

    /**
     * With the feature on, the redemption locks the tenant's enforcement row
     * (an upsert, then a locking read), then the code's connection and the
     * rule's connections in one statement in ascending id order, and only then
     * the code; nothing is locked out of that order.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheLocksAreTakenInThePackagesOrder(): void
    {
        config()->set('sso.features.enforcement', true);

        $code = $this->issue();

        $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$this->other->id, $this->connection->id]]);
        $this->recordLockOrder();

        self::assertTrue($this->redeem($code)->isRedeemed());

        $ids = [$this->connection->id, $this->other->id];

        sort($ids, SORT_STRING);

        self::assertSame(['enforcement upsert', 'enforcement', 'connections ' . implode(', ', $ids), 'code'], $this->lockOrder());
    }

    /**
     * A tenant with no rule stored is locked through an unconfigured row, and
     * the code is redeemed with nothing required.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATenantWithNoRuleIsLockedThroughAnUnconfiguredRow(): void
    {
        config()->set('sso.features.enforcement', true);

        $code = $this->issue();

        $this->recordLockOrder();

        self::assertTrue($this->redeem($code)->isRedeemed());
        self::assertSame(['enforcement upsert', 'enforcement', 'connections ' . $this->connection->id, 'code'], $this->lockOrder());
        self::assertNull(TenantEnforcement::query()->sole()->version);
    }

    /**
     * With the feature off, the redemption locks the connection and then the
     * code: no statement names the enforcement table, no row is inserted, and
     * the inheritance contract is never asked.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWithTheFeatureOffNoEnforcementIsLockedOrAsked(): void
    {
        $inheritance = new ScriptedInheritance(['tenant-1']);
        $code        = $this->issue();

        $this->app?->instance(EnforcementInheritance::class, $inheritance);
        $this->recordLockOrder();

        self::assertTrue($this->redeem($code)->isRedeemed());
        self::assertSame(['connections ' . $this->connection->id . ', tenant-1', 'code'], $this->lockOrder());
        self::assertSame(0, $this->enforcementStatements());
        self::assertSame(0, TenantEnforcement::query()->count());
        self::assertSame([], $inheritance->asked());
    }

    /**
     * Rows of `[column]`: what a code names that its locks were taken for.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideBindings(): iterable
    {
        yield 'the connection' => ['connection_id'];
        yield 'the application' => ['application'];
    }

    /**
     * A code that, once locked, no longer names the connection or the
     * application its plain read did, and its locks were taken for, is
     * `handoff_unknown`, and stays unconsumed: no other tenant's rule is locked
     * out of order.
     *
     * @param  string  $column
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideBindings')]
    public function testACodeThatNoLongerNamesWhatItWasLockedForIsUnknown(string $column): void
    {
        $code = $this->issue();

        $this->afterTheTenantIsRead(function () use ($code, $column): void {
            StoredCode::query()->whereKey($this->stored($code)->id)->update([$column => $column === 'application' ? 'mobile' : $this->other->id]);
        });

        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->redeem($code)->reason);
        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame([], $this->singleUseKeys());
        self::assertSame([], $this->linkerAsked);
    }

    /**
     * A connection deleted between the plain read of its tenant and its lock is
     * `connection_unavailable`, and the code stays unconsumed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAConnectionDeletedBeforeItsLockIsUnavailable(): void
    {
        $code = $this->issue();

        $this->afterTheTenantIsRead(function (): void {
            Connection::query()->whereKey($this->connection->id)->delete();
        });

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->redeem($code)->reason);
        self::assertNull($this->stored($code)->redeemed_at);
    }

    /**
     * An inheritance contract that names another enforcing tenant by the
     * recheck than when the locks were taken is `connection_unavailable`, with
     * the code consumed and nothing acknowledged.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnEnforcingTenantThatMovedSinceTheLockIsUnavailable(): void
    {
        config()->set('sso.features.enforcement', true);

        $inheritance = new ScriptedInheritance(['tenant-1', 'parent-1']);
        $code        = $this->issue();

        $this->app?->instance(EnforcementInheritance::class, $inheritance);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->redeem($code)->reason);
        self::assertSame([['tenant-1', 'web'], ['tenant-1', 'web']], $inheritance->asked());
        self::assertNotNull($this->stored($code)->redeemed_at);
        self::assertFalse($this->reloaded($this->connection)->has_completed_sign_in);
        self::assertSame([], $this->linkerAsked);
    }

    /**
     * A connection disabled, left incomplete or deleted since completion is
     * `connection_unavailable`; a disabled or incomplete one consumes the code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAConnectionNoLongerUsableSinceCompletion(): void
    {
        $disabled   = $this->issue();
        $incomplete = $this->issue();
        $deleted    = $this->issue();

        $this->connection->forceFill(['enabled' => false])->save();

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->redeem($disabled)->reason);
        self::assertNotNull($this->stored($disabled)->redeemed_at);

        $this->connection->forceFill(['enabled' => true, 'settings' => []])->save();

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->redeem($incomplete)->reason);
        self::assertNotNull($this->stored($incomplete)->redeemed_at);

        $this->connection->delete();

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->redeem($deleted)->reason);
        self::assertNull($this->stored($deleted)->redeemed_at);
        self::assertCount(2, $this->singleUseKeys());
        self::assertSame([], $this->linkerAsked);
    }

    /**
     * Each code, whether it is linked and redeemed, and whether a completed
     * sign-in is acknowledged.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: bool, 2: bool, 3: bool}>
     */
    public static function acknowledgements(): iterable
    {
        yield 'a linked sign_in' => [Purpose::SIGN_IN, true, true, true];
        yield 'an unlinked sign_in' => [Purpose::SIGN_IN, false, true, false];
        yield 'a link' => [Purpose::LINK, true, true, false];
        yield 'an unlinked link' => [Purpose::LINK, false, true, false];
        yield 'a reauthenticate' => [Purpose::REAUTHENTICATE, true, true, false];
        yield 'a sign_in never redeemed' => [Purpose::SIGN_IN, true, false, false];
    }

    /**
     * Only a linked `sign_in` redeemed acknowledges a completed sign-in: a
     * `link`, a `reauthenticate`, an unlinked `sign_in` and a code issued but
     * never redeemed leave the connection's flag unset.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  bool  $linked
     * @param  bool  $redeemed
     * @param  bool  $acknowledged
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('acknowledgements')]
    public function testOnlyALinkedSignInRedeemedAcknowledgesACompletedSignIn(Purpose $purpose, bool $linked, bool $redeemed, bool $acknowledged): void
    {
        if ($purpose !== Purpose::SIGN_IN) {
            $this->readyForTheFlowsIdentity();
        }

        if (!$linked) {
            $this->linked = null;
        }

        $code = $this->issue($purpose);

        if ($redeemed) {
            self::assertTrue($this->redeem($code, purpose: $purpose)->isRedeemed());
        }

        self::assertSame($acknowledged, $this->reloaded($this->connection)->has_completed_sign_in);
        self::assertFalse($this->reloaded($this->other)->has_completed_sign_in);
    }

    /**
     * A connection that has completed a sign-in keeps its flag, and is written
     * nothing more by another.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnAcknowledgedConnectionIsNotWrittenAgain(): void
    {
        $this->redeem($this->issue());

        $stamped = $this->reloaded($this->connection)->updated_at->toIso8601String();

        $this->clock->advance(10);

        self::assertTrue($this->redeem($this->issue())->isRedeemed());
        self::assertTrue($this->reloaded($this->connection)->has_completed_sign_in);
        self::assertSame($stamped, $this->reloaded($this->connection)->updated_at->toIso8601String());
    }

    /**
     * The verifier a code's challenge was made from, the one presented, and the
     * reason.
     *
     * @return iterable<string, array{0: string, 1: string, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function verifiers(): iterable
    {
        $shortest = str_repeat('a', 42) . '~';
        $longest  = str_repeat('-._~', 31) . 'abcd';

        yield '43 characters' => [$shortest, $shortest, null];
        yield '128 characters' => [$longest, $longest, null];
        yield '42 characters' => [$shortest, substr($shortest, 0, 42), FailureReason::VERIFIER_MISMATCH];
        yield '129 characters' => [$longest, $longest . 'e', FailureReason::VERIFIER_MISMATCH];
        yield 'a reserved character' => [self::VERIFIER, substr(self::VERIFIER, 0, 42) . '+', FailureReason::VERIFIER_MISMATCH];
        yield 'the verifier in another case' => [self::VERIFIER, strtoupper(self::VERIFIER), FailureReason::VERIFIER_MISMATCH];
    }

    /**
     * Verifiers of 43 and 128 unreserved characters redeem the code their
     * challenge was made from; one of 42 or 129, or with a reserved character,
     * is `verifier_mismatch`.
     *
     * @param  string  $verifier
     * @param  string  $presented
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('verifiers')]
    public function testTheVerifierLengths(string $verifier, string $presented, ?FailureReason $reason): void
    {
        $code = $this->issue(verifier: $verifier);

        self::assertSame($reason, $this->redeem($code, $presented)->reason);
    }

    /**
     * A reference, a challenge, a verifier or a digest is never accepted as a
     * code, and a code or a challenge never as a verifier.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testCodesReferencesAndVerifiersAreNeverAcceptedAsOneAnother(): void
    {
        $code = $this->issue();

        foreach ([self::REFERENCE, self::CHALLENGE, self::VERIFIER, hash('sha256', $code)] as $notACode) {
            self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->redeem($notACode)->reason);
        }

        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame(FailureReason::VERIFIER_MISMATCH, $this->redeem($code, $code)->reason);
        self::assertSame(FailureReason::VERIFIER_MISMATCH, $this->redeem($this->issue(), self::CHALLENGE)->reason);
    }

    /**
     * Values that name no code.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function unknownCodes(): iterable
    {
        yield 'empty' => [''];
        yield '42 characters' => [str_repeat('A', 42)];
        yield '44 characters' => [str_repeat('A', 44)];
        yield 'a character outside base64url' => [str_repeat('A', 42) . '+'];
        yield 'a trailing newline' => [str_repeat('A', 43) . "\n"];
        yield 'a code never issued' => [str_repeat('A', 43)];
    }

    /**
     * A value that is not 43 base64url characters, and a code never issued, are
     * `handoff_unknown`, and record nothing.
     *
     * @param  string  $value
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('unknownCodes')]
    public function testAnUnknownCodeIsRefused(string $value): void
    {
        $this->issue();

        $answer = $this->redeem($value);

        self::assertTrue($answer->isRefused());
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $answer->reason);
        self::assertSame([], $this->singleUseKeys());
    }

    /**
     * A full limit on the IP address is `rate_limited` with the wait to the end
     * of the window, before the code is read; every attempt counts, an unknown
     * code included.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFullLimitIsRateLimited(): void
    {
        $code = $this->issue(expiresAt: $this->clock->now()->addMinutes(5));

        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->redeem('not-a-code')->reason);

        $limited = $this->redeem($code);

        self::assertTrue($limited->isRateLimited());
        self::assertFalse($limited->isRefused());
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(60, $limited->retryAfter);
        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame([], $this->singleUseKeys());

        $this->clock->advance(60);

        self::assertTrue($this->redeem($code)->isRedeemed());
    }

    /**
     * Stored results the package did not write.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function corruptResults(): iterable
    {
        foreach (['not JSON', 'a JSON string', 'not a result', 'another purpose', 'another application', 'another connection', 'another reference', 'another tenant'] as $variant) {
            yield $variant => [$variant];
        }
    }

    /**
     * A stored result the package did not write is an
     * `UnexpectedValueException`, and the code stays unconsumed.
     *
     * @param  string  $variant
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    #[DataProvider('corruptResults')]
    public function testACorruptStoredResultPropagates(string $variant): void
    {
        $code   = $this->issue();
        $stored = match ($variant) {
            'not JSON'            => 'not json',
            'a JSON string'       => '"a result"',
            'not a result'        => '{"issuer":1}',
            'another purpose'     => $this->encoded($this->verifiedResult(Purpose::LINK)),
            'another application' => $this->encoded($this->verifiedResult(application: 'mobile')),
            'another connection'  => $this->encoded($this->verifiedResult(connectionId: $this->other->id)),
            'another tenant'      => $this->encoded($this->verifiedResult(tenantId: 'tenant-2')),
            default               => $this->encoded($this->verifiedResult(reference: 'Dq8tVv3w0kLmNoPqRsTuVwXyZ0123456')),
        };

        $this->stored($code)->forceFill(['result' => app(SecretEncrypter::class)->encrypt($stored)])->save();

        try {
            $this->redeem($code);

            self::fail('A corrupt stored result was redeemed.');
        } catch (\UnexpectedValueException $exception) {
            self::assertStringNotContainsString('person@example.com', $exception->getMessage());
        }

        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame([], $this->singleUseKeys());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * A result bound to another code is refused with the package's own message.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResultBoundToAnotherCodeNamesNoPart(): void
    {
        $code = $this->issue();

        $this->stored($code)->forceFill(['result' => app(SecretEncrypter::class)->encrypt($this->encoded($this->verifiedResult(Purpose::LINK)))])->save();

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A handoff code\'s stored result is not one the package wrote.');

        $this->redeem($code);
    }

    /**
     * A stored result no key decrypts propagates, and the code stays
     * unconsumed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testACiphertextNoKeyDecryptsPropagates(): void
    {
        $code = $this->issue();

        $this->stored($code)->forceFill(['result' => 'not a ciphertext'])->save();

        try {
            $this->redeem($code);

            self::fail('A result no key decrypts was redeemed.');
        } catch (DecryptException $exception) {
            self::assertSame('The payload is invalid.', $exception->getMessage());
        }

        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame(0, DB::table(StorageConnection::table('single_use.table'))->count());
    }

    /**
     * A database error propagates as a server error, never as a refusal, and
     * leaves the code unconsumed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testADatabaseErrorPropagates(): void
    {
        $code = $this->issue();

        Schema::connection(StorageConnection::name())->dropIfExists(StorageConnection::table('single_use.table'));

        try {
            $this->redeem($code);

            self::fail('A database error was answered.');
        } catch (QueryException) {
            self::assertNull($this->stored($code)->redeemed_at);
        }
    }

    /**
     * Rows of `[whether the code resolved to an identity]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideSignIns(): iterable
    {
        yield 'linked' => [true];
        yield 'unlinked' => [false];
    }

    /**
     * A `sign_in` code, linked or unlinked, is never redeemed standalone: it is
     * a `LogicException`, the code is left unconsumed, and the same code
     * redeems inside a transaction.
     *
     * @param  bool  $linked
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    #[DataProvider('provideSignIns')]
    public function testAStandaloneSignInIsRefusedAndLeavesTheCodeUnconsumed(bool $linked): void
    {
        if (!$linked) {
            $this->linked = null;
        }

        $code = $this->issue();

        try {
            app(HandoffRedemption::class)->redeem(Purpose::SIGN_IN, 'web', $this->connection->id, $code, self::VERIFIER);
            self::fail('A sign-in was redeemed with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame('A [sign_in] or [reauthenticate] code is redeemed through admit(), in the caller\'s transaction (decision D5).', $exception->getMessage());
        }

        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame([], $this->singleUseKeys());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertTrue($this->redeem($code)->isRedeemed());
    }

    /**
     * Rows of `[purpose]`: each purpose the standalone path refuses.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose}>
     */
    public static function provideSessionPurposes(): iterable
    {
        yield 'a sign_in' => [Purpose::SIGN_IN];
        yield 'a reauthenticate' => [Purpose::REAUTHENTICATE];
    }

    /**
     * A single-use store that is not transactional, such as a shared cache,
     * keeps whatever it records when the redemption rolls back; the standalone
     * path refuses a `sign_in` or a `reauthenticate` code before it records
     * anything there, so the same code still redeems through `admit()`.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    #[DataProvider('provideSessionPurposes')]
    public function testTheStandaloneRefusalRecordsNothingInANonTransactionalStore(Purpose $purpose): void
    {
        $store = new class implements SingleUseStore {
            /** @var array<string, true> Every key recorded, kept whatever rolls back. */
            public array $recorded = [];

            /**
             * Record the key unless it was recorded before.
             *
             * @param  string  $namespace
             * @param  string  $key
             * @param  \Carbon\CarbonImmutable  $until
             * @return \SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome
             */
            #[\Override]
            public function record(string $namespace, #[\SensitiveParameter] string $key, CarbonImmutable $until): SingleUseOutcome
            {
                unset($until);

                if (isset($this->recorded["{$namespace}:{$key}"])) {
                    return SingleUseOutcome::SEEN;
                }

                $this->recorded["{$namespace}:{$key}"] = true;

                return SingleUseOutcome::RECORDED;
            }

            /**
             * Every key recorded so far, in order.
             *
             * @return list<string>
             */
            public function keys(): array
            {
                return array_keys($this->recorded);
            }
        };

        $this->app?->instance(SingleUseStore::class, $store);

        $code = $this->issue($purpose);

        try {
            app(HandoffRedemption::class)->redeem($purpose, 'web', $this->connection->id, $code, self::VERIFIER);
            self::fail('A session purpose was redeemed with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame('A [sign_in] or [reauthenticate] code is redeemed through admit(), in the caller\'s transaction (decision D5).', $exception->getMessage());
        }

        self::assertSame([], $store->keys());
        self::assertNull($this->stored($code)->redeemed_at);

        if ($purpose === Purpose::REAUTHENTICATE) {
            return;
        }

        self::assertTrue($this->redeem($code)->isRedeemed());
        self::assertSame([HandoffRedemption::NAMESPACE . ':' . hash('sha256', $code)], $store->keys());
    }

    /**
     * Rows of `[the code's purpose, whether it resolved to an identity]`: each
     * code a standalone `link` endpoint may be handed that is not a link.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: bool}>
     */
    public static function provideCodesOfAnotherPurpose(): iterable
    {
        yield 'a linked sign_in' => [Purpose::SIGN_IN, true];
        yield 'an unlinked sign_in' => [Purpose::SIGN_IN, false];
        yield 'a reauthenticate' => [Purpose::REAUTHENTICATE, true];
    }

    /**
     * A `sign_in` or `reauthenticate` code presented to the standalone path
     * asked for a `link` is the client's error, never a `LogicException`: it is
     * consumed and refused as `purpose_mismatch`, committed, and redeeming it
     * afterwards for its own purpose is a replay.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  bool  $linked
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    #[DataProvider('provideCodesOfAnotherPurpose')]
    public function testACodeOfAnotherPurposeAskedForAsALinkIsAPurposeMismatch(Purpose $purpose, bool $linked): void
    {
        if (!$linked) {
            $this->linked = null;
        }

        $code    = $this->issue($purpose);
        $refused = app(HandoffRedemption::class)->redeem(Purpose::LINK, 'web', $this->connection->id, $code, self::VERIFIER, new IdentityReference('App\Models\User', '7'));

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::PURPOSE_MISMATCH, $refused->reason);
        self::assertNull($refused->result);
        self::assertFalse($refused->isAdmitted());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame('2026-11-01T09:30:00+00:00', $this->stored($code)->redeemed_at?->toIso8601String());
        self::assertCount(1, $this->singleUseKeys());
        self::assertSame(FailureReason::REPLAYED, $this->redeem($code, self::VERIFIER, $purpose)->reason);
        self::assertFalse($this->reloaded($this->connection)->has_completed_sign_in);
        self::assertSame([], $this->linkerAsked);
    }

    /**
     * Issue a code through the package's store for the purpose, linked to the
     * identity the test holds, with the challenge of the verifier, expiring a
     * minute from now unless given.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  string  $verifier
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issue(Purpose $purpose = Purpose::SIGN_IN, ?CarbonImmutable $expiresAt = null, string $verifier = self::VERIFIER): string
    {
        $grant = new HandoffGrant(
            result: $this->verifiedResult($purpose),
            challenge: S256Challenge::of(Verifier::fromString($verifier)),
            expiresAt: $expiresAt ?? $this->clock->now()->addMinute(),
            trustVersion: $this->connection->trust_version,
            linkedIdentity: $this->linked,
            identity: $purpose  === Purpose::SIGN_IN ? null : new IdentityReference('App\Models\User', '7'),
            sessionId: $purpose === Purpose::REAUTHENTICATE ? 'session-1' : null,
            sessionNotAfter: CarbonImmutable::parse('2026-11-01T18:00:00Z'),
            linkId: $this->linked === null ? null : ExampleLinks::linkId($this->linked),
        );

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DatabaseHandoffStore::class)->issue($grant)->code->reveal();
    }

    /**
     * Redeem the code with what is presented: by default, a `sign_in` for `web`
     * through the connection with the client's verifier.
     *
     * @param  string  $code
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  ?string  $connectionId
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeem(
        string $code,
        string $verifier = self::VERIFIER,
        Purpose $purpose = Purpose::SIGN_IN,
        string $application = 'web',
        ?string $connectionId = null,
    ): RedemptionResult {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $caller = $purpose === Purpose::LINK ? new IdentityReference('App\Models\User', '7') : null;

        $redemption = $app->make(HandoffRedemption::class);
        $connection = $connectionId ?? $this->connection->id;

        return DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => $redemption->redeem($purpose, $application, $connection, $code, $verifier, $caller),
        );
    }

    /**
     * The verified result a code carries: through the connection, of
     * `tenant-1`, for `web`, with the reference, unless given otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  ?string  $connectionId
     * @param  string  $reference
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function verifiedResult(
        Purpose $purpose = Purpose::SIGN_IN,
        string $application = 'web',
        ?string $connectionId = null,
        string $reference = self::REFERENCE,
        string $tenantId = 'tenant-1',
    ): VerifiedResult {
        return new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $connectionId ?? $this->connection->id,
            tenantId: $tenantId,
            protocol: VerifyingDriver::NAME,
            application: $application,
            purpose: $purpose,
            requestReference: RequestReference::fromString($reference),
            attributes: ['email' => 'person@example.com', 'groups' => ['staff', 'admins']],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext(CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd']),
        );
    }

    /**
     * Run the change once, straight after the redemption's plain read of its
     * connection's tenant and before any lock, as a change committed between
     * the two would.
     *
     * @param  \Closure(): void  $change
     * @return void
     */
    private function afterTheTenantIsRead(\Closure $change): void
    {
        $done = false;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($change, &$done): void {
            $isTenantRead = preg_match('/^select ["`]?tenant_id["`]? from/', strtolower($query->sql)) === 1;

            if ($done || !$isTenantRead) {
                return;
            }

            $done = true;

            $change();
        });
    }

    /**
     * The JSON the store encrypts for the result.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return string
     */
    private function encoded(VerifiedResult $result): string
    {
        return (string) json_encode($result->toArray());
    }

    /**
     * The stored row of the code, read again.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\Sso\Models\HandoffCode
     */
    private function stored(string $code): StoredCode
    {
        return StoredCode::query()->where('code_digest', hash('sha256', $code))->sole();
    }

    /**
     * The connection, read again.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function reloaded(Connection $connection): Connection
    {
        return Connection::query()->whereKey($connection->id)->sole();
    }

    /**
     * Each single-use key held: its namespace, key digest and expiry.
     *
     * @return list<array{0: string, 1: string, 2: string}>
     */
    private function singleUseKeys(): array
    {
        $keys = [];

        foreach (DB::table(StorageConnection::table('single_use.table'))->orderBy('expires_at')->get() as $row) {
            $keys[] = [(string) $row->namespace, (string) $row->key_digest, CarbonImmutable::parse((string) $row->expires_at, 'UTC')->toIso8601String()];
        }

        return $keys;
    }

    /**
     * A linking contract that answers through the closure.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
     * @return \SineMacula\Laravel\Sso\Contracts\Linker
     */
    private static function linker(\Closure $resolve): Linker
    {
        return new readonly class ($resolve) implements Linker {
            /**
             * Constructor.
             *
             * @param  \Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
             */
            public function __construct(

                /** What every result resolves to. */
                private \Closure $resolve,
            ) {}

            /**
             * What the closure answers.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result): LinkResolution
            {
                return ExampleLinks::resolution(($this->resolve)($result));
            }
        };
    }

    /**
     * Bind what a `link` or a `reauthenticate` code needs to be redeemed by the
     * identity it was started for: the subject linked to that identity, a fresh
     * caller, an eligible identity and a session bound to its link.
     *
     * @return void
     */
    private function readyForTheFlowsIdentity(): void
    {
        $this->linked = new IdentityReference('App\Models\User', '7');

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(LinkEligibility::class, new AllowingLinkEligibility);
        $this->app?->instance(ReauthenticationSessions::class, new RecordingSessions(ExampleLinks::linkId($this->linked)));

        $storage = new DelegatingLinkStorage(app(LinkStore::class));

        $storage->answering = fn (): LinkResolution => ExampleLinks::resolution($this->linked);

        $this->app?->instance(Linker::class, $storage);
    }
}
