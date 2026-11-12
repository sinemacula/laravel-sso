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
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
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
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\RecordsLockOrder;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Clients;
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
 * Feature tests for redeeming a handoff code from the package's own store.
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
    use FailsDatabaseStatements, RecordsEventSequences, RecordsLockOrder, UsesConnections, UsesEnforcement;

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

    /** @var \SineMacula\Laravel\Sso\Http\ClientContext The client every redemption is made for. */
    private ClientContext $client;

    /**
     * Bind a fixed clock, a linker and the client, and create two connections.
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
        $this->client = new ClientContext('203.0.113.7', 'Example/1.0');
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
     * A `sign_in` code is redeemed, consumed, recorded and acknowledged.
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
     * A `link` or `reauthenticate` code answers its identity and session.
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
     * A code failing several checks is refused for the first in order.
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
     * A wrong purpose, application, connection or verifier consumes the code.
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
     * A code redeems until a second before its expiry and expires at it.
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
     * A voided code is `handoff_unknown`, neither consumed nor recorded.
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
     * A code the single-use store has seen is `replayed` and not consumed.
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
     * A link changed since completion is `link_changed` and stays consumed.
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
     * An unlinked handoff redeems without acknowledging a sign-in.
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
     * Enforcement turned on since completion is judged under the locks.
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
     * The redemption never asks the exemption contract.
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
     * The redemption locks enforcement, then connections by id, then the code.
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
     * A tenant with no rule is locked through an unconfigured row.
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
     * With the feature off, only the connection and the code are locked.
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
     * A code no longer naming what its locks cover is `handoff_unknown`.
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
     * A connection deleted before its lock is `connection_unavailable`.
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
     * An enforcing tenant that moved since the lock is unavailable.
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
     * A connection unusable since completion is `connection_unavailable`.
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
     * Each code, whether it is linked and redeemed, and if it acknowledges.
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
     * Only a linked `sign_in` redeemed acknowledges a completed sign-in.
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
     * A connection already acknowledged is not written again.
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
     * The verifier the challenge was made from, the one presented, the reason.
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
     * Verifiers of 43 to 128 unreserved characters redeem; others do not.
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
     * Codes, references, verifiers and digests are never interchangeable.
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
     * A malformed or never-issued code is `handoff_unknown`.
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
     * A full limit is `rate_limited` before the code is read.
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
     * Rows of `[code, limited, verifier, reason]`; `null` reason redeems.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: string, 3: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideReports(): iterable
    {
        yield 'redeemed' => ['issued', false, self::VERIFIER, null];
        yield 'rate limited' => ['issued', true, self::VERIFIER, FailureReason::RATE_LIMITED];
        yield 'not a code' => ['not-a-code', false, self::VERIFIER, FailureReason::HANDOFF_UNKNOWN];
        yield 'another verifier' => ['issued', false, str_repeat('v', 43), FailureReason::VERIFIER_MISMATCH];
    }

    /**
     * What a redemption reports carries the client it was given.
     *
     * @param  string  $code
     * @param  bool  $limited
     * @param  string  $verifier
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideReports')]
    public function testWhatARedemptionReportsCarriesTheClientItWasGiven(string $code, bool $limited, string $verifier, ?FailureReason $reason): void
    {
        $issued = $this->issue(expiresAt: $this->clock->now()->addMinutes(5));

        if ($limited) {
            config()->set('sso.rate_limits.redemption.per_ip', ['max' => 1, 'decay_seconds' => 60]);
            $this->redeem('not-a-code');
        }

        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));
        $this->startRecordingEvents();

        $this->redeem($code === 'issued' ? $issued : $code, $verifier);

        $event = $reason === null ? $this->recordedEvents()[0] ?? null : $this->assertExactlyOneFailure(Flow::REDEMPTION, $reason);

        if ($reason === null) {
            self::assertInstanceOf(HandoffRedeemed::class, $event);
        }

        self::assertNotNull($event);
        self::assertSame(['203.0.113.7', 'Example/1.0'], [$event->context()->ip, $event->context()->userAgent]);
    }

    /**
     * A redemption for a client with no IP address counts against no address.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedemptionForNoClientCountsNoAddress(): void
    {
        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->client = new ClientContext(null, null);

        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->redeem('not-a-code')->reason);
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->redeem('not-a-code')->reason);
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
     * A corrupt stored result propagates and leaves the code unconsumed.
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
     * A stored result no key decrypts propagates; the code stays unconsumed.
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
     * A database error propagates and leaves the code unconsumed.
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
     * A standalone `sign_in` is a `LogicException`; the code stays unconsumed.
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
            app(HandoffRedemption::class)->redeem(Purpose::SIGN_IN, 'web', $this->connection->id, $code, self::VERIFIER, Clients::browser());
            self::fail('A sign-in was redeemed with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame('A [sign_in] or [reauthenticate] code is redeemed through admit(), in the caller\'s transaction.', $exception->getMessage());
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
     * The standalone refusal records nothing in a non-transactional store.
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
            app(HandoffRedemption::class)->redeem($purpose, 'web', $this->connection->id, $code, self::VERIFIER, Clients::browser());
            self::fail('A session purpose was redeemed with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame('A [sign_in] or [reauthenticate] code is redeemed through admit(), in the caller\'s transaction.', $exception->getMessage());
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
     * Rows of `[the code's purpose, whether it resolved to an identity]`.
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
     * A non-`link` code redeemed standalone as a `link` is `purpose_mismatch`.
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
        $refused = app(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            'web',
            $this->connection->id,
            $code,
            self::VERIFIER,
            Clients::browser(),
            new Caller(new IdentityReference('App\Models\User', '7')),
        );

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
     * Rows of `[how many attempts deadlock]`, each leaving one to succeed.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideStandaloneDeadlocks(): iterable
    {
        yield 'the first' => [1];
        yield 'all but the last' => [2];
    }

    /**
     * A standalone `link` is retried after a deadlock and redeems once.
     *
     * @param  int  $deadlocks
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    #[DataProvider('provideStandaloneDeadlocks')]
    public function testAStandaloneLinkIsTriedAgainAfterADeadlock(int $deadlocks): void
    {
        $this->readyForTheFlowsIdentity();

        $code = $this->issue(Purpose::LINK);

        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 2, 'decay_seconds' => 60]);

        $this->deadlockStatement(self::onTable('update', StorageConnection::table('handoff_codes.table')), $deadlocks);
        $this->startRecordingEvents();

        $answer = $this->redeemAlone($code);

        self::assertTrue($answer->isRedeemed());
        self::assertFalse($answer->isAdmitted());
        self::assertSame($deadlocks, $this->databaseFailuresFired());
        self::assertSame([HandoffRedeemed::class], array_map(static fn (object $event): string => $event::class, $this->recordedEvents()));
        self::assertSame('2026-11-01T09:30:00+00:00', $this->stored($code)->redeemed_at?->toIso8601String());
        self::assertCount(1, $this->singleUseKeys());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());

        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->redeemAlone('not-a-code')->reason);
        self::assertTrue($this->redeemAlone('not-a-code')->isRateLimited());
    }

    /**
     * A standalone `link` is retried after a serialisation failure in a
     * savepoint, which Laravel throws in a form it would not retry.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testAStandaloneLinkIsTriedAgainAfterASerializationFailureInASavepoint(): void
    {
        $this->readyForTheFlowsIdentity();

        $code = $this->issue(Purpose::LINK);

        $this->failToSerialiseStatement(self::onTable('insert', StorageConnection::table('single_use.table')));
        $this->startRecordingEvents();

        $answer = $this->redeemAlone($code);

        self::assertTrue($answer->isRedeemed());
        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame([HandoffRedeemed::class], array_map(static fn (object $event): string => $event::class, $this->recordedEvents()));
        self::assertNotNull($this->stored($code)->redeemed_at);
        self::assertCount(1, $this->singleUseKeys());
    }

    /**
     * A standalone `link` gives up after three deadlocks, unconsumed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testAStandaloneLinkGivesUpAfterThreeDeadlocks(): void
    {
        $this->readyForTheFlowsIdentity();

        $code = $this->issue(Purpose::LINK);

        $this->deadlockStatement(self::onTable('update', StorageConnection::table('handoff_codes.table')), 4);
        $this->startRecordingEvents();

        try {
            $this->redeemAlone($code);

            self::fail('A redemption deadlocked three times was answered.');
        } catch (QueryException $exception) {
            self::assertTrue(self::isInjectedFailure($exception));
        }

        self::assertSame(3, $this->databaseFailuresFired());
        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame([], $this->singleUseKeys());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        $this->assertNoEvents();

        $this->disarmDatabaseFailures();

        self::assertTrue($this->redeemAlone($code)->isRedeemed());
    }

    /**
     * Inside the caller's transaction a deadlock propagates without retry.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testInsideTheCallersTransactionADeadlockPropagates(): void
    {
        $this->readyForTheFlowsIdentity();

        $code     = $this->issue(Purpose::LINK);
        $database = DB::connection(StorageConnection::name());

        $this->deadlockStatement(self::onTable('update', StorageConnection::table('handoff_codes.table')), 2);

        $database->beginTransaction();

        try {
            $this->redeemAlone($code);

            self::fail('A redemption deadlocked inside the caller\'s transaction was answered.');
        } catch (\PDOException $exception) {
            self::assertTrue(self::isInjectedFailure($exception));
            self::assertSame(1, $database->transactionLevel());
        } finally {
            $database->rollBack();
        }

        self::assertSame(1, $this->databaseFailuresFired());
        self::assertNull($this->stored($code)->redeemed_at);

        $this->disarmDatabaseFailures();

        self::assertTrue($this->redeem($code, purpose: Purpose::LINK)->isRedeemed());
    }

    /**
     * Issue a code for the purpose, expiring in a minute by default.
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
     * Redeem the code, by default as a `sign_in` for `web`.
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

        $caller = $purpose === Purpose::LINK ? new Caller(new IdentityReference('App\Models\User', '7')) : null;

        $redemption = $app->make(HandoffRedemption::class);
        $connection = $connectionId ?? $this->connection->id;
        $client     = $this->client;

        return DB::connection(StorageConnection::name())->transaction(
            static fn (): RedemptionResult => $redemption->redeem($purpose, $application, $connection, $code, $verifier, $client, $caller),
        );
    }

    /**
     * Redeem the `link` code as its flow's identity in the open transaction.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Throwable
     */
    private function redeemAlone(string $code): RedemptionResult
    {
        return app(HandoffRedemption::class)->redeem(
            Purpose::LINK,
            'web',
            $this->connection->id,
            $code,
            self::VERIFIER,
            $this->client,
            new Caller(new IdentityReference('App\Models\User', '7')),
        );
    }

    /**
     * The verified result a code carries, for `tenant-1` and `web` by default.
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
     * Run the change once, between the plain read of the tenant and the lock.
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
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                return ExampleLinks::resolution(($this->resolve)($result));
            }
        };
    }

    /**
     * Bind what a `link` or `reauthenticate` code needs to redeem.
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
