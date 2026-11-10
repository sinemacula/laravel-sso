<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\CiphertextWrite;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyStatus;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for the management helpers of a connection's own keys (SSO-2.5,
 * SSO-2.7, SSO-2.11, SSO-2.12): every outcome of adding, making current and
 * retiring a key; the first key of a use made current at once; a second `next`
 * key refused; the overlap a replaced key is kept for; tenant scoping; the
 * exact freshness operation and maximum age asked; a stale caller refused with
 * nothing written and nothing reported; a state changed between the first read
 * and the transaction refused; the listing's order; signing and encryption keys
 * rotated on their own; every read made on the write connection; and a private
 * key stored only as the encrypter's ciphertext, which a failed write never
 * quotes.
 *
 * Keys are generated on P-256 wherever the type does not matter, since RSA
 * generation is slow; the class generates one RSA key, to show the default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-import-type Replacement from \SineMacula\Laravel\Sso\Keys\KeyService
 */
#[CoversClass(KeyService::class)]
#[CoversClass(CiphertextWrite::class)]
final class KeyServiceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The tenant whose connection the helpers act on. */
    private const string TENANT = 'tenant-1';

    /** @var string A key id no row has. */
    private const string UNKNOWN = '01jbunknownkey000000000000';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helpers ask. */
    private RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's SAML connection. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Identities\Caller Who makes each change. */
    private Caller $actor;

    /**
     * Bind a fixed clock and a recording freshness contract, create the tables
     * and a SAML connection, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->freshness = new RecordingFreshness;
        $this->actor     = new Caller(new IdentityReference('App\Models\User', '42'));

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);

        $this->startRecordingEvents();
    }

    /**
     * The first key of a use is added as current, made current now, and
     * reported as added and then made current, with nothing it replaced.
     *
     * @return void
     */
    public function testTheFirstKeyOfAUseBecomesCurrent(): void
    {
        $result = $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA, $this->actor);
        $key    = self::summaryOf($result);

        self::assertSame(KeyStatus::ADDED, $result->status);
        self::assertTrue($result->isSucceeded());
        self::assertSame($this->connection->id, $key->connectionId);
        self::assertSame(KeyUse::SP_SIGNING, $key->use);
        self::assertSame(KeyState::CURRENT, $key->state);
        self::assertSame(KeyType::RSA, $key->type);
        self::assertSame(3072, $key->bits);
        self::assertSame('2026-11-01T09:30:00+00:00', $key->madeCurrentAt?->toIso8601String());
        self::assertNull($key->retiringUntil);
        self::assertNotNull($key->key->certificate);

        $this->assertEventSequence([KeyAdded::class, KeyMadeCurrent::class]);

        [$added, $madeCurrent] = $this->recordedEvents();

        self::assertInstanceOf(KeyAdded::class, $added);
        self::assertSame($key->id, $added->keyId);
        self::assertSame(KeyUse::SP_SIGNING, $added->use);
        self::assertSame(KeyState::CURRENT, $added->state);
        self::assertSame($key->key->fingerprint, $added->fingerprint);
        self::assertEquals($key->notAfter, $added->notAfter);
        self::assertSame('42', $added->context->actingIdentityId);
        self::assertSame(self::TENANT, $added->context->connectionTenantId);

        self::assertInstanceOf(KeyMadeCurrent::class, $madeCurrent);
        self::assertSame($key->id, $madeCurrent->keyId);
        self::assertNull($madeCurrent->previousKeyId);

        $row = ConnectionKey::query()->findOrFail($key->id);

        self::assertSame('current', $row->getRawOriginal('state'));
        self::assertSame('2026-11-01 09:30:00', $row->getRawOriginal('made_current_at'));
    }

    /**
     * A key added while the use has a current key is added as next, reported as
     * added only.
     *
     * @return void
     */
    public function testALaterKeyIsAddedAsNext(): void
    {
        $this->add();
        $this->startRecordingEvents();

        $key = self::summaryOf($this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA, $this->actor));

        self::assertSame(KeyState::NEXT, $key->state);
        self::assertNull($key->madeCurrentAt);

        $this->assertEventSequence([KeyAdded::class]);

        $added = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyAdded::class, $added);
        self::assertSame(KeyState::NEXT, $added->state);
    }

    /**
     * A second next key of a use is a conflict, refused before freshness is
     * asked, with nothing written or reported.
     *
     * @return void
     */
    public function testASecondNextKeyIsAConflict(): void
    {
        $this->add();
        $this->add();
        $this->freshness->reset();
        $this->startRecordingEvents();

        $before = $this->rows();
        $result = $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA, $this->actor);

        self::assertTrue($result->isRefused());
        self::assertSame(FailureReason::KEY_STATE_CONFLICT, $result->reason);
        self::assertNull($result->key);
        self::assertSame([], $this->freshness->asked());
        self::assertSame($before, $this->rows());
        $this->assertNoEvents();
    }

    /**
     * Each use rotates on its own, and a key's type is RSA, of the configured
     * modulus, unless another is given.
     *
     * @return void
     */
    public function testEachUseRotatesOnItsOwnAndTheTypeDefaultsToRsa(): void
    {
        $this->add();
        $this->add();

        $key = self::summaryOf($this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_ENCRYPTION, Clients::browser()));

        self::assertSame(KeyUse::SP_ENCRYPTION, $key->use);
        self::assertSame(KeyState::CURRENT, $key->state);
        self::assertSame(KeyType::RSA, $key->type);
        self::assertSame(3072, $key->bits);
    }

    /**
     * An OIDC connection's `private_key_jwt` key is added the same way.
     *
     * @return void
     */
    public function testAnOidcConnectionHasAClientAssertionKey(): void
    {
        $oidc = $this->makeConnection(['protocol' => 'oidc']);
        $key  = self::summaryOf($this->keys()->addNext(self::TENANT, $oidc->id, KeyUse::CLIENT_ASSERTION, Clients::browser(), KeyType::EC));

        self::assertSame(KeyUse::CLIENT_ASSERTION, $key->use);
        self::assertSame(KeyState::CURRENT, $key->state);
        self::assertSame($oidc->id, $key->connectionId);
    }

    /**
     * Rows of `[protocol, use, type, violations]`: a use or type not allowed
     * for the connection, and what is refused.
     *
     * @return iterable<string, array{
     *     0: string,
     *     1: \SineMacula\Laravel\Sso\Keys\Enums\KeyUse,
     *     2: \SineMacula\Laravel\Sso\Keys\Enums\KeyType,
     *     3: list<array{setting: string, code: string}>
     * }>
     */
    public static function provideRefusedUses(): iterable
    {
        $use  = ['setting' => 'use', 'code' => 'not_allowed'];
        $type = ['setting' => 'key_type', 'code' => 'not_allowed'];

        yield from [
            'a trusted certificate\'s use' => ['saml2', KeyUse::IDP_SIGNING, KeyType::RSA, [$use]],
            'an anchor\'s use'             => ['saml2', KeyUse::METADATA_SIGNING, KeyType::RSA, [$use]],
            'an ec signing key'            => ['saml2', KeyUse::SP_SIGNING, KeyType::EC, [$type]],
            'an oidc use on saml'          => ['saml2', KeyUse::CLIENT_ASSERTION, KeyType::EC, [$use]],
            'a saml use on oidc'           => ['oidc', KeyUse::SP_SIGNING, KeyType::RSA, [$use]],
            'an application\'s protocol'   => ['cas', KeyUse::SP_SIGNING, KeyType::RSA, [$use]],
            'an ec encryption key'         => ['saml2', KeyUse::SP_ENCRYPTION, KeyType::EC, [$type]],
            'both'                         => ['oidc', KeyUse::SP_ENCRYPTION, KeyType::EC, [$use, $type]],
        ];
    }

    /**
     * A use or type not allowed for the connection is invalid, refused before
     * freshness is asked, with nothing written or reported.
     *
     * @param  string  $protocol
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  list<array{setting: string, code: string}>  $violations
     * @return void
     */
    #[DataProvider('provideRefusedUses')]
    public function testRefusesAUseOrTypeNotAllowed(string $protocol, KeyUse $use, KeyType $type, array $violations): void
    {
        $connection = $this->makeConnection(['protocol' => $protocol]);
        $result     = $this->keys()->addNext(self::TENANT, $connection->id, $use, Clients::browser(), $type, $this->actor);

        self::assertTrue($result->isInvalid());
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame($violations, $result->jsonSerialize()['violations']);
        self::assertSame([], $this->freshness->asked());
        self::assertSame([], $this->rows());
        $this->assertNoEvents();
    }

    /**
     * Rows of `[operation]`: each helper that takes a connection.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOperations(): iterable
    {
        yield from [
            'add next'             => ['addNext'],
            'make current'         => ['makeCurrent'],
            'retire'               => ['retire'],
            'trust certificate'    => ['trustCertificate'],
            'distrust certificate' => ['distrustCertificate'],
        ];
    }

    /**
     * A connection that is unknown, or another tenant's, is not found, the same
     * answer for each, before freshness is asked and with nothing written or
     * reported.
     *
     * @param  string  $operation
     * @return void
     */
    #[DataProvider('provideOperations')]
    public function testAConnectionOfAnotherTenantIsNotFound(string $operation): void
    {
        $theirs = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2']);
        $key    = $this->add();

        $this->freshness->reset();
        $this->startRecordingEvents();

        $before = $this->rows();

        $elsewhere = [
            [self::TENANT, $theirs->id],
            ['tenant-2', $this->connection->id],
            [self::TENANT, self::UNKNOWN],
            [self::TENANT, ''],
            [self::TENANT, str_repeat('a', 27)],
        ];

        foreach ($elsewhere as [$tenant, $connection]) {

            $result = $this->callOperation($operation, $tenant, $connection, $key->id);

            self::assertTrue($result->isRefused());
            self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $result->reason);
        }

        self::assertSame([], $this->freshness->asked());
        self::assertSame($before, $this->rows());
        $this->assertNoEvents();
    }

    /**
     * The listing of a connection that is unknown, or another tenant's, is
     * `null`.
     *
     * @return void
     */
    public function testTheListingOfAnotherTenantsConnectionIsNull(): void
    {
        $theirs = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2']);

        $this->add();

        self::assertNull($this->keys()->keys(self::TENANT, $theirs->id));
        self::assertNull($this->keys()->keys('tenant-2', $this->connection->id));
        self::assertNull($this->keys()->keys(self::TENANT, self::UNKNOWN));
        self::assertSame([], $this->keys()->keys('tenant-2', $theirs->id));
    }

    /**
     * An empty tenant id is the application's mistake.
     *
     * @return void
     */
    public function testAnEmptyTenantIdIsAMistake(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A tenant id is 1 to 255 bytes.');

        $this->keys()->addNext('', $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA);
    }

    /**
     * Each helper asks the freshness contract once, with its own operation
     * (`sso.keys.rotate` for a key, `sso.connection.trust` for a certificate)
     * and that operation's configured maximum age.
     *
     * @return void
     */
    public function testAsksTheExactOperationAndMaximumAge(): void
    {
        config()->set('sso.freshness.max_age_seconds.keys_rotate', 120);
        config()->set('sso.freshness.max_age_seconds.connection_trust', 90);

        $first  = $this->add();
        $second = $this->add();

        $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $second->id, Clients::browser(), $this->actor);
        $this->keys()->retire(self::TENANT, $this->connection->id, $first->id, Clients::browser(), $this->actor);

        $certificate = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser(), $this->actor));

        $this->keys()->distrustCertificate(self::TENANT, $this->connection->id, $certificate->id, Clients::browser(), $this->actor);

        $rotate = [FreshnessOperation::KEYS_ROTATE, 120];
        $trust  = [FreshnessOperation::CONNECTION_TRUST, 90];

        self::assertSame([$rotate, $rotate, $rotate, $rotate, $trust, $trust], $this->freshness->asked());
    }

    /**
     * Rows of `[operation]`: each mutation.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMutations(): iterable
    {
        return self::provideOperations();
    }

    /**
     * A caller whose authentication is not fresh enough, asked about as given,
     * is refused with `freshness_required`: nothing is written and nothing is
     * reported.
     *
     * @param  string  $operation
     * @return void
     */
    #[DataProvider('provideMutations')]
    public function testAStaleCallerIsRefusedWithNothingWritten(string $operation): void
    {
        $keyId = $this->prepare($operation);

        $this->freshness->answer(FreshnessOutcome::STALE);
        $this->freshness->reset();
        $this->startRecordingEvents();

        $before = $this->rows();
        $result = $this->callOperation($operation, self::TENANT, $this->connection->id, $keyId);

        self::assertTrue($result->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertNull($result->key);
        self::assertCount(1, $this->freshness->asked());
        self::assertSame([$this->actor], $this->freshness->callers());
        self::assertSame($before, $this->rows());
        $this->assertNoEvents();
    }

    /**
     * Making the next key current makes the current key of its use retiring,
     * accepted until the configured overlap ends, and reports the change with
     * the key it replaced.
     *
     * @return void
     */
    public function testMakingTheNextKeyCurrentRetiresTheCurrentOne(): void
    {
        config()->set('sso.keys.overlap_seconds', 3600);

        $current = $this->add();

        $this->clock->advance(60);

        $next = $this->add();

        $this->clock->advance(60);
        $this->startRecordingEvents();

        $result   = $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $next->id, Clients::browser(), $this->actor);
        $key      = self::summaryOf($result);
        $previous = $result->previous;

        self::assertSame(KeyStatus::MADE_CURRENT, $result->status);
        self::assertSame($next->id, $key->id);
        self::assertSame(KeyState::CURRENT, $key->state);
        self::assertSame('2026-11-01T09:32:00+00:00', $key->madeCurrentAt?->toIso8601String());
        self::assertNull($key->retiringUntil);

        self::assertNotNull($previous);
        self::assertSame($current->id, $previous->id);
        self::assertSame(KeyState::RETIRING, $previous->state);
        self::assertSame('2026-11-01T09:30:00+00:00', $previous->madeCurrentAt?->toIso8601String());
        self::assertSame('2026-11-01T10:32:00+00:00', $previous->retiringUntil?->toIso8601String());

        $this->assertEventSequence([KeyMadeCurrent::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyMadeCurrent::class, $event);
        self::assertSame($next->id, $event->keyId);
        self::assertSame($current->id, $event->previousKeyId);

        $retiring = ConnectionKey::query()->findOrFail($current->id);

        self::assertSame('retiring', $retiring->getRawOriginal('state'));
        self::assertSame('2026-11-01 10:32:00', $retiring->getRawOriginal('retiring_until'));
        self::assertSame('current', ConnectionKey::query()->findOrFail($next->id)->getRawOriginal('state'));
    }

    /**
     * Making a signing key current retires only the current signing key: the
     * current encryption key stays current, with no overlap, and still the only
     * key that decrypts, however long the overlap runs.
     *
     * @return void
     */
    public function testMakingAKeyCurrentRetiresOnlyTheCurrentKeyOfItsUse(): void
    {
        config()->set('sso.keys.overlap_seconds', 3600);

        // Added first, so a promotion that ignored the use would find it.
        $encryption = self::summaryOf($this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_ENCRYPTION, Clients::browser()));
        $signing    = $this->add();
        $next       = $this->add();

        $result = $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $next->id, Clients::browser());
        $stored = ConnectionKey::query()->findOrFail($encryption->id);

        self::assertSame(KeyState::CURRENT, $encryption->state);
        self::assertSame(KeyStatus::MADE_CURRENT, $result->status);
        self::assertSame($signing->id, $result->previous?->id);
        self::assertSame('retiring', ConnectionKey::query()->findOrFail($signing->id)->getRawOriginal('state'));
        self::assertSame('current', $stored->getRawOriginal('state'));
        self::assertNull($stored->getRawOriginal('retiring_until'));
        self::assertSame($encryption->id, $this->ring()->current($this->connection->id, KeyUse::SP_ENCRYPTION)?->id);
        self::assertSame([$encryption->id], array_map(static fn (KeySummary $key): string => $key->id, $this->ring()->decryption($this->connection->id)));

        $this->clock->advance(3601);

        self::assertSame([$encryption->id], array_map(static fn (KeySummary $key): string => $key->id, $this->ring()->decryption($this->connection->id)));
    }

    /**
     * An overlap of none ends as the key is replaced: it is no longer accepted.
     *
     * @return void
     */
    public function testAnOverlapOfNoneEndsAtOnce(): void
    {
        config()->set('sso.keys.overlap_seconds', 0);

        $this->add();

        $next     = $this->add();
        $previous = $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $next->id, Clients::browser())->previous;

        self::assertNotNull($previous);
        self::assertSame('2026-11-01T09:30:00+00:00', $previous->retiringUntil?->toIso8601String());
    }

    /**
     * Only a next key of the service provider's own is made current: the
     * current key, a retiring key and a trusted certificate are a conflict, and
     * a key that is not the connection's is not found; each before freshness is
     * asked, with nothing written or reported.
     *
     * @return void
     */
    public function testOnlyANextKeyIsMadeCurrent(): void
    {
        $other       = $this->makeConnection(['protocol' => 'saml2']);
        $retiring    = $this->add();
        $current     = $this->add();
        $certificate = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser()));
        $theirs      = $this->add($other);

        $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $current->id, Clients::browser());

        self::assertSame(KeyState::CURRENT, $theirs->state);

        $this->freshness->reset();
        $this->startRecordingEvents();

        $before = $this->rows();

        foreach ([$current->id, $retiring->id, $certificate->id] as $keyId) {
            self::assertSame(FailureReason::KEY_STATE_CONFLICT, $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $keyId, Clients::browser())->reason);
        }

        foreach ([$theirs->id, self::UNKNOWN, '', str_repeat('a', 27)] as $keyId) {
            self::assertSame(FailureReason::KEY_NOT_FOUND, $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $keyId, Clients::browser())->reason);
        }

        self::assertSame([], $this->freshness->asked());
        self::assertSame($before, $this->rows());
        $this->assertNoEvents();
    }

    /**
     * A retiring key, or a next key never made current, is retired and removed,
     * and reported with the key as it was.
     *
     * @return void
     */
    public function testRetiresARetiringOrNextKey(): void
    {
        $retiring = $this->add();
        $current  = $this->add();

        $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $current->id, Clients::browser());

        $next = $this->add();

        $this->startRecordingEvents();

        $result = $this->keys()->retire(self::TENANT, $this->connection->id, $retiring->id, Clients::browser(), $this->actor);
        $key    = self::summaryOf($result);

        self::assertSame(KeyStatus::RETIRED, $result->status);
        self::assertSame($retiring->id, $key->id);
        self::assertSame(KeyState::RETIRING, $key->state);
        self::assertNotNull($key->retiringUntil);

        $this->assertEventSequence([KeyRetired::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyRetired::class, $event);
        self::assertSame($retiring->id, $event->keyId);
        self::assertSame($retiring->key->fingerprint, $event->fingerprint);

        $retired = self::summaryOf($this->keys()->retire(self::TENANT, $this->connection->id, $next->id, Clients::browser(), $this->actor));

        self::assertSame(KeyState::NEXT, $retired->state);
        self::assertSame([$current->id], array_column($this->rows(), 'id'));
    }

    /**
     * The current key and a trusted certificate are never retired: a conflict;
     * a key that is not the connection's is not found; each before freshness is
     * asked, with nothing written or reported.
     *
     * @return void
     */
    public function testNeverRetiresTheCurrentKeyOrACertificate(): void
    {
        $other       = $this->makeConnection(['protocol' => 'saml2']);
        $current     = $this->add();
        $certificate = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser()));
        $theirs      = $this->add($other);

        $this->freshness->reset();
        $this->startRecordingEvents();

        $before = $this->rows();

        self::assertSame(FailureReason::KEY_STATE_CONFLICT, $this->keys()->retire(self::TENANT, $this->connection->id, $current->id, Clients::browser())->reason);
        self::assertSame(FailureReason::KEY_STATE_CONFLICT, $this->keys()->retire(self::TENANT, $this->connection->id, $certificate->id, Clients::browser())->reason);
        self::assertSame(FailureReason::KEY_NOT_FOUND, $this->keys()->retire(self::TENANT, $this->connection->id, $theirs->id, Clients::browser())->reason);
        self::assertSame(FailureReason::KEY_NOT_FOUND, $this->keys()->retire(self::TENANT, $this->connection->id, self::UNKNOWN, Clients::browser())->reason);

        self::assertSame([], $this->freshness->asked());
        self::assertSame($before, $this->rows());
        $this->assertNoEvents();
    }

    /**
     * A next key added between the first read and the transaction makes the
     * addition a conflict: the key generated is never written.
     *
     * @return void
     */
    public function testANextKeyAddedMeanwhileIsAConflict(): void
    {
        $this->add();

        $this->freshness->onCheck = function (): void {
            $this->add();
        };

        $result = $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA);

        self::assertSame(FailureReason::KEY_STATE_CONFLICT, $result->reason);
        self::assertCount(2, $this->rows());
    }

    /**
     * A key made current between the first read and the transaction makes
     * making it current, or retiring it, a conflict.
     *
     * @return void
     */
    public function testAKeyMadeCurrentMeanwhileIsAConflict(): void
    {
        $current = $this->add();
        $next    = $this->add();

        $this->freshness->onCheck = function () use ($next): void {
            $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $next->id, Clients::browser());
        };

        self::assertSame(FailureReason::KEY_STATE_CONFLICT, $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $next->id, Clients::browser())->reason);

        $newer = $this->add();

        $this->freshness->onCheck = function () use ($newer): void {
            $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $newer->id, Clients::browser());
        };

        self::assertSame(FailureReason::KEY_STATE_CONFLICT, $this->keys()->retire(self::TENANT, $this->connection->id, $newer->id, Clients::browser())->reason);
        self::assertSame(KeyState::RETIRING, ConnectionKey::query()->findOrFail($current->id)->state);
        self::assertSame(KeyState::CURRENT, ConnectionKey::query()->findOrFail($newer->id)->state);
    }

    /**
     * A key removed between the first read and the transaction is not found.
     *
     * @return void
     */
    public function testAKeyRemovedMeanwhileIsNotFound(): void
    {
        $this->add();

        $next = $this->add();

        $this->freshness->onCheck = function () use ($next): void {
            $this->keys()->retire(self::TENANT, $this->connection->id, $next->id, Clients::browser());
        };

        self::assertSame(FailureReason::KEY_NOT_FOUND, $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $next->id, Clients::browser())->reason);
    }

    /**
     * A connection removed between the first read and the transaction is not
     * found, and nothing is written.
     *
     * @return void
     */
    public function testAConnectionRemovedMeanwhileIsNotFound(): void
    {
        $this->freshness->onCheck = function (): void {
            $this->connection->delete();
        };

        $result = $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA);

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $result->reason);
        self::assertSame([], $this->rows());
    }

    /**
     * The private key is stored only as the bound encrypter's ciphertext, which
     * decrypts to the key pair's private half, and no result, listing or
     * serialisation shows it.
     *
     * @return void
     */
    public function testThePrivateKeyIsStoredOnlyAsCiphertext(): void
    {
        $result = $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA);
        $key    = self::summaryOf($result);
        $row    = ConnectionKey::query()->findOrFail($key->id);
        $stored = $row->getRawOriginal('private_key');

        self::assertIsString($stored);
        self::assertStringNotContainsString('PRIVATE KEY', $stored);

        /** @var \SineMacula\Laravel\Sso\Contracts\SecretEncrypter $encrypter */
        $encrypter = $this->app?->make(SecretEncrypter::class);
        $pem       = $encrypter->decrypt($stored);
        $private   = openssl_pkey_get_private($pem);

        self::assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $pem);
        self::assertNotFalse($private);
        self::assertSame($row->public_key, openssl_pkey_get_details($private)['key'] ?? null);
        self::assertSame($key->key->publicKey, $row->public_key);
        self::assertSame(['CN' => $this->connection->id], openssl_x509_parse((string) $row->certificate)['subject'] ?? null);

        foreach ([json_encode($result), json_encode($this->keys()->keys(self::TENANT, $this->connection->id)), json_encode($row), print_r($result, true)] as $view) {
            self::assertIsString($view);
            self::assertStringNotContainsString('PRIVATE KEY', $view);
            self::assertStringNotContainsString($stored, $view);
        }
    }

    /**
     * A failed insert of a key propagates as a server error that quotes nothing
     * of the encrypted private key, chains nothing that does, and writes and
     * reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedWriteNeverQuotesThePrivateKey(): void
    {
        $this->add();

        Schema::connection(StorageConnection::name())->table((new ConnectionKey)->getTable(), static function (Blueprint $table): void {
            $table->dropColumn('updated_at');
        });

        $before = $this->rows();

        $this->startRecordingEvents();

        try {
            $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA);
            self::fail('The failed write was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertMatchesRegularExpression('/^The connection\'s key could not be written \(SQLSTATE [0-9A-Z]{5}\)\.$/', $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }

        self::assertSame($before, $this->rows());
        $this->assertNoEvents();
    }

    /**
     * Every read is made on the write connection (SSO-11.3), the checks made
     * before the transaction among them: with the read connection unusable,
     * every helper still answers.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $current = $this->add();
        $next    = $this->add();
        $id      = $this->connection->id;
        $keys    = $this->keys();

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $listed     = $keys->keys(self::TENANT, $id);
            $conflict   = $keys->addNext(self::TENANT, $id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA);
            $promoted   = $keys->makeCurrent(self::TENANT, $id, $next->id, Clients::browser());
            $retired    = $keys->retire(self::TENANT, $id, $current->id, Clients::browser());
            $trusted    = $keys->trustCertificate(self::TENANT, $id, Certificates::distinct(0), Clients::browser());
            $distrusted = $keys->distrustCertificate(self::TENANT, $id, self::summaryOf($trusted)->id, Clients::browser());
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame([$current->id, $next->id], array_map(static fn (KeySummary $key): string => $key->id, $listed ?? []));
        self::assertSame(FailureReason::KEY_STATE_CONFLICT, $conflict->reason);
        self::assertSame(KeyStatus::MADE_CURRENT, $promoted->status);
        self::assertSame(KeyStatus::RETIRED, $retired->status);
        self::assertSame(KeyStatus::TRUSTED, $trusted->status);
        self::assertSame(KeyStatus::DISTRUSTED, $distrusted->status);
    }

    /**
     * The listing holds every key and certificate of the connection, by use,
     * then current, next, retiring and a certificate's none, then oldest first.
     *
     * @return void
     */
    public function testListsEveryKeyInOrder(): void
    {
        $retiring = $this->add();

        $this->clock->advance(1);

        $first = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(1), Clients::browser()));

        $this->clock->advance(1);

        $current = $this->add();

        $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $current->id, Clients::browser());
        $this->clock->advance(1);

        $second = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(2), Clients::browser()));
        $next   = $this->add();
        $keys   = $this->keys()->keys(self::TENANT, $this->connection->id);

        self::assertNotNull($keys);
        self::assertSame(
            [$current->id, $next->id, $retiring->id, $first->id, $second->id],
            array_map(static fn (KeySummary $key): string => $key->id, $keys),
        );
        self::assertSame(['current', 'next', 'retiring', null, null], array_map(static fn (KeySummary $key): ?string => $key->state?->value, $keys));
    }

    /**
     * The listing orders by use before state, and by state before age: an older
     * key of a later use, or an older next key, never comes first.
     *
     * @return void
     */
    public function testListsByUseAndStateBeforeAge(): void
    {
        $encryption = $this->add();

        ConnectionKey::query()->whereKey($encryption->id)->update(['use' => KeyUse::SP_ENCRYPTION->value]);

        $current = $this->add();
        $next    = $this->add();

        ConnectionKey::query()->whereKey($current->id)->update(['created_at' => '2026-11-01 09:30:02']);
        ConnectionKey::query()->whereKey($next->id)->update(['created_at' => '2026-11-01 09:30:01']);
        ConnectionKey::query()->whereKey($encryption->id)->update(['created_at' => '2026-11-01 09:30:00']);

        $keys = $this->keys()->keys(self::TENANT, $this->connection->id);

        self::assertSame([$current->id, $next->id, $encryption->id], array_map(static fn (KeySummary $key): string => $key->id, $keys ?? []));
    }

    /**
     * A certificate the inspector refuses is invalid with the inspector's
     * violation, before freshness is asked, with nothing written.
     *
     * @return void
     */
    public function testRefusesACertificateTheInspectorRefuses(): void
    {
        $result = $this->keys()->trustCertificate(self::TENANT, $this->connection->id, 'not a certificate', Clients::browser());

        self::assertTrue($result->isInvalid());
        self::assertSame([['setting' => 'certificate', 'code' => 'invalid_format']], $result->jsonSerialize()['violations']);
        self::assertSame([], $this->freshness->asked());
        self::assertSame([], $this->rows());
    }

    /**
     * A certificate the connection already trusts is a duplicate, and the
     * eleventh is one too many, each refused before freshness is asked; the
     * tenth is still trusted.
     *
     * @return void
     */
    public function testRefusesADuplicateAndAnEleventhCertificate(): void
    {
        for ($index = 1; $index <= KeyService::MAX_TRUSTED_CERTIFICATES; $index++) {
            self::assertTrue($this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct($index), Clients::browser())->isSucceeded());
        }

        $this->freshness->reset();

        $duplicate = $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(1), Clients::browser());
        $tooMany   = $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(11), Clients::browser());

        self::assertTrue($duplicate->isInvalid());
        self::assertSame([['setting' => 'certificate', 'code' => 'duplicate']], $duplicate->jsonSerialize()['violations']);
        self::assertTrue($tooMany->isInvalid());
        self::assertSame([['setting' => 'certificate', 'code' => 'too_many']], $tooMany->jsonSerialize()['violations']);
        self::assertCount(KeyService::MAX_TRUSTED_CERTIFICATES, $this->rows());
        self::assertSame([], $this->freshness->asked());
    }

    /**
     * A key id no key can have, empty or longer than an id, is not found
     * without a query of the keys.
     *
     * @return void
     */
    public function testAKeyIdNoKeyCanHaveIsNotFoundWithoutAQuery(): void
    {
        $this->add();

        $statements = $this->recordKeyStatements();

        self::assertSame(FailureReason::KEY_NOT_FOUND, $this->keys()->makeCurrent(self::TENANT, $this->connection->id, '', Clients::browser())->reason);
        self::assertSame(FailureReason::KEY_NOT_FOUND, $this->keys()->retire(self::TENANT, $this->connection->id, self::UNKNOWN . 'x', Clients::browser())->reason);
        self::assertSame([], $statements->getArrayCopy());

        self::assertSame(FailureReason::KEY_NOT_FOUND, $this->keys()->retire(self::TENANT, $this->connection->id, self::UNKNOWN, Clients::browser())->reason);
        self::assertCount(1, $statements);
    }

    /**
     * A next key is made current even where no key of its use is current, with
     * no key it replaced.
     *
     * @return void
     */
    public function testANextKeyIsMadeCurrentWhereNoneIsCurrent(): void
    {
        $retiring = $this->add();
        $next     = $this->add();

        ConnectionKey::query()->whereKey($retiring->id)->update(['state' => KeyState::RETIRING->value]);

        $result = $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $next->id, Clients::browser());

        self::assertSame(KeyStatus::MADE_CURRENT, $result->status);
        self::assertSame(KeyState::CURRENT, self::summaryOf($result)->state);
        self::assertNull($result->previous);
        self::assertSame('retiring', ConnectionKey::query()->findOrFail($retiring->id)->getRawOriginal('state'));
    }

    /**
     * The keys are read locked for update inside each change's transaction, and
     * never by the listing or the checks made before it. SQLite has no row
     * lock, so there the lock is compiled to a marker comment to show it was
     * asked for.
     *
     * @return void
     */
    public function testLocksTheKeysOnlyInsideTheTransaction(): void
    {
        $current    = $this->add();
        $statements = $this->recordKeyStatements(true);
        $id         = $this->connection->id;
        $keys       = $this->keys();
        $next       = $this->add();

        $keys->keys(self::TENANT, $id);
        $keys->makeCurrent(self::TENANT, $id, $next->id, Clients::browser());
        $keys->retire(self::TENANT, $id, $current->id, Clients::browser());
        $keys->distrustCertificate(
            self::TENANT,
            $id,
            self::summaryOf($keys->trustCertificate(self::TENANT, $id, Certificates::distinct(0), Clients::browser()))->id,
            Clients::browser(),
        );

        $reads = $statements->getArrayCopy();

        self::assertContains(true, array_column($reads, 'locked'));
        self::assertContains(false, array_column($reads, 'locked'));
        self::assertSame(array_column($reads, 'transaction'), array_column($reads, 'locked'));
    }

    /**
     * Replacing the trusted signing certificates trusts exactly those given:
     * one no longer given is distrusted and reported retired, one newly given
     * is trusted and reported added, one kept is left as it was, and a metadata
     * signing anchor is untouched; the flows in flight are voided and the trust
     * version raised once, and no freshness is asked.
     *
     * @return void
     */
    public function testReplacingTheTrustedCertificatesTrustsExactlyThoseGiven(): void
    {
        $id      = $this->connection->id;
        $kept    = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $id, Certificates::distinct(0), Clients::browser()));
        $dropped = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $id, Certificates::distinct(1), Clients::browser()));
        $anchor  = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $id, Certificates::distinct(4), Clients::browser(), use: KeyUse::METADATA_SIGNING));
        $request = $this->makeAuthorizationRequest($this->connection);
        $before  = Connection::query()->findOrFail($id)->trust_version;

        $this->freshness->reset();
        $this->startRecordingEvents();

        $changes = $this->replace([Certificates::distinct(0), Certificates::distinct(2)]);

        self::assertSame([], $changes['violations']);
        self::assertSame(
            [[KeyUse::IDP_SIGNING, self::fingerprintOf(Certificates::distinct(2))]],
            array_map(static fn (KeySummary $key): array => [$key->use, $key->key->fingerprint], $changes['added']),
        );
        self::assertSame([$dropped->id], array_map(static fn (KeySummary $key): string => $key->id, $changes['retired']));
        self::assertSame([$anchor->id], ConnectionKey::query()->where('use', KeyUse::METADATA_SIGNING->value)->pluck('id')->all());
        self::assertTrue(ConnectionKey::query()->whereKey($kept->id)->exists());
        self::assertSame(self::sortedFingerprints([Certificates::distinct(0), Certificates::distinct(2)]), $this->trustedFingerprints());
        self::assertSame($before + 1, Connection::query()->findOrFail($id)->trust_version);
        self::assertNotNull($request->refresh()->voided_at);
        self::assertSame([], $this->freshness->asked());

        $this->assertEventSequence([KeyRetired::class, KeyAdded::class]);

        [$retired, $added] = $this->recordedEvents();

        self::assertInstanceOf(KeyRetired::class, $retired);
        self::assertInstanceOf(KeyAdded::class, $added);
        self::assertSame([$dropped->id, '42'], [$retired->keyId, $retired->context->actingIdentityId]);
        self::assertSame([$changes['added'][0]->id, '42'], [$added->keyId, $added->context->actingIdentityId]);
    }

    /**
     * Replacing the certificates with those trusted and another adds it alone,
     * which voids nothing and leaves the trust version as it was; replacing
     * them with exactly those trusted changes and reports nothing.
     *
     * @return void
     */
    public function testAnAdditiveReplacementVoidsNothing(): void
    {
        $id = $this->connection->id;

        $this->keys()->trustCertificate(self::TENANT, $id, Certificates::distinct(0), Clients::browser());

        $request = $this->makeAuthorizationRequest($this->connection);
        $before  = Connection::query()->findOrFail($id)->trust_version;

        $this->startRecordingEvents();

        $added = $this->replace([Certificates::distinct(0), Certificates::distinct(1)]);

        self::assertSame([1, 0, []], [count($added['added']), count($added['retired']), $added['violations']]);
        $this->assertEventSequence([KeyAdded::class]);

        $this->startRecordingEvents();

        self::assertSame(['added' => [], 'retired' => [], 'violations' => []], $this->replace([Certificates::distinct(1), Certificates::distinct(0)]));
        self::assertSame($before, Connection::query()->findOrFail($id)->trust_version);
        self::assertNull($request->refresh()->voided_at);

        $this->assertNoEvents();
    }

    /**
     * Rows of `[certificates, violations]`: certificates a replacement refuses,
     * and each violation, at the certificate's position.
     *
     * @return iterable<string, array{0: \Closure(): list<string>, 1: list<array{setting: string, code: string}>}>
     */
    public static function provideRefusedReplacements(): iterable
    {
        yield from [
            'an elliptic curve' => [static fn (): array => [Certificates::distinct(0), Certificates::ecP256()], [['setting' => 'certificate.1', 'code' => 'unsupported']]],
            'one given twice'   => [static fn (): array => [Certificates::distinct(0), Certificates::distinct(0)], [['setting' => 'certificate.1', 'code' => 'duplicate']]],
            'not a certificate' => [static fn (): array => ['not a certificate', Certificates::distinct(0)], [['setting' => 'certificate.0', 'code' => 'invalid_format']]],
            'a weak key'        => [static fn (): array => [Certificates::rsa1024()], [['setting' => 'certificate.0', 'code' => 'weak_key']]],
            'a private key'     => [static fn (): array => [Certificates::privateKey()], [['setting' => 'certificate.0', 'code' => 'private_key_refused']]],
            'eleven'            => [
                static fn (): array => array_map(Certificates::distinct(...), range(0, 10)),
                [['setting' => 'certificate.10', 'code' => 'too_many']],
            ],
            'two refused' => [
                static fn (): array => [Certificates::ecP256(), Certificates::distinct(0), Certificates::distinct(0)],
                [['setting' => 'certificate.0', 'code' => 'unsupported'], ['setting' => 'certificate.2', 'code' => 'duplicate']],
            ],
        ];
    }

    /**
     * A replacement any of whose certificates is refused names each violation
     * and writes, voids and reports nothing; ten certificates are accepted.
     *
     * @param  \Closure(): list<string>  $certificates
     * @param  list<array{setting: string, code: string}>  $violations
     * @return void
     */
    #[DataProvider('provideRefusedReplacements')]
    public function testARefusedReplacementWritesNothing(\Closure $certificates, array $violations): void
    {
        $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(11), Clients::browser());

        $request = $this->makeAuthorizationRequest($this->connection);
        $before  = $this->rows();

        $this->startRecordingEvents();

        $changes = $this->replace($certificates());

        self::assertSame([[], []], [$changes['added'], $changes['retired']]);
        self::assertSame($violations, array_map(static fn (SettingViolation $violation): array => $violation->jsonSerialize(), $changes['violations']));
        self::assertSame($before, $this->rows());
        self::assertNull($request->refresh()->voided_at);

        $this->assertNoEvents();

        $ten = $this->replace(array_map(Certificates::distinct(...), range(0, 9)));

        self::assertSame([10, 1, []], [count($ten['added']), count($ten['retired']), $ten['violations']]);
    }

    /**
     * Every read of the keys a replacement makes under the connection's lock
     * locks what it reads.
     *
     * @return void
     */
    public function testAReplacementLocksEveryKeyItReads(): void
    {
        $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser());

        $statements = $this->recordKeyStatements(true);

        $this->replace([Certificates::distinct(1)]);

        self::assertNotSame([], $statements->getArrayCopy());
        self::assertSame([true], array_values(array_unique(array_column($statements->getArrayCopy(), 'locked'))));
    }

    /**
     * Add a P-256 signing key to the connection, the tenant's own unless
     * another is given, and answer its summary.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private function add(?Connection $connection = null): KeySummary
    {
        $connection ??= $this->connection;

        return self::summaryOf($this->keys()->addNext($connection->tenant_id, $connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA, $this->actor));
    }

    /**
     * Put the connection in a state the mutation can act on, and answer the id
     * of the key it acts on.
     *
     * @param  string  $operation
     * @return string
     */
    private function prepare(string $operation): string
    {
        $current = $this->add();

        return match ($operation) {
            'makeCurrent'         => $this->add()->id,
            'retire'              => $this->retiring($current)->id,
            'distrustCertificate' => self::summaryOf($this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser()))->id,
            default               => self::UNKNOWN,
        };
    }

    /**
     * Make the key retiring, by adding a next key and making it current.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $current
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private function retiring(KeySummary $current): KeySummary
    {
        $previous = $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $this->add()->id, Clients::browser())->previous;

        self::assertNotNull($previous);
        self::assertSame($current->id, $previous->id);

        return $previous;
    }

    /**
     * Call the helper of the operation for the tenant's connection and key.
     *
     * @param  string  $operation
     * @param  string  $tenant
     * @param  string  $connection
     * @param  string  $keyId
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     */
    private function callOperation(string $operation, string $tenant, string $connection, string $keyId): KeyResult
    {
        $keys = $this->keys();

        return match ($operation) {
            'addNext'          => $keys->addNext($tenant, $connection, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA, $this->actor),
            'makeCurrent'      => $keys->makeCurrent($tenant, $connection, $keyId, Clients::browser(), $this->actor),
            'retire'           => $keys->retire($tenant, $connection, $keyId, Clients::browser(), $this->actor),
            'trustCertificate' => $keys->trustCertificate($tenant, $connection, Certificates::rsa2048(), Clients::browser(), $this->actor),
            default            => $keys->distrustCertificate($tenant, $connection, $keyId, Clients::browser(), $this->actor),
        };
    }

    /**
     * Every row of the keys table, as stored, by id.
     *
     * @return list<array<string, mixed>>
     */
    private function rows(): array
    {
        return array_values(ConnectionKey::query()->orderBy('id')->get()->map(static fn (ConnectionKey $key): array => $key->getAttributes())->all());
    }

    /**
     * Record each read of the keys table from now on: whether it was made
     * inside a transaction, and whether it locked the rows for update; on
     * SQLite, with the lock compiled to a marker comment when asked.
     *
     * @param  bool  $markLocks
     * @return \ArrayObject<int, array{transaction: bool, locked: bool}>
     */
    private function recordKeyStatements(bool $markLocks = false): \ArrayObject
    {
        $database = DB::connection(StorageConnection::name());

        if ($markLocks && $database->getDriverName() === 'sqlite') {
            $database->setQueryGrammar(new class ($database) extends SQLiteGrammar {
                /**
                 * Compile a lock for update to a marker comment.
                 *
                 * @param  \Illuminate\Database\Query\Builder  $query
                 * @param  bool|string  $value
                 * @return string
                 */
                #[\Override]
                protected function compileLock(Builder $query, $value): string
                {
                    return $value === true ? ' /* for update */' : '';
                }
            });
        }

        $table = (new ConnectionKey)->getTable();
        $level = $database->transactionLevel();

        /** @var \ArrayObject<int, array{transaction: bool, locked: bool}> $statements */
        $statements = new \ArrayObject;

        $database->listen(static function (QueryExecuted $query) use ($statements, $table, $level): void {

            $sql = strtolower($query->sql);

            if (!str_starts_with($sql, 'select') || !str_contains($sql, $table)) {
                return;
            }

            $statements[] = ['transaction' => $query->connection->transactionLevel() > $level, 'locked' => str_ends_with(rtrim($sql, ' */'), 'for update')];
        });

        return $statements;
    }

    /**
     * Replace the connection's trusted signing certificates with those given,
     * inside a transaction holding the connection's lock.
     *
     * @param  list<string>  $certificates
     * @return Replacement
     */
    private function replace(array $certificates): array
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($certificates): array {

            $locked = Connection::query()->whereKey($this->connection->id)->lockForUpdate()->firstOrFail();

            return $this->keys()->replaceTrustedCertificatesLocked($locked, $certificates, Clients::browser(), $this->actor);
        });
    }

    /**
     * The fingerprints of the signing certificates the connection trusts,
     * sorted.
     *
     * @return list<string>
     */
    private function trustedFingerprints(): array
    {
        $fingerprints = array_filter(ConnectionKey::query()->where('use', KeyUse::IDP_SIGNING->value)->pluck('fingerprint')->all(), is_string(...));

        sort($fingerprints);

        return $fingerprints;
    }

    /**
     * The fingerprints of the certificates, sorted.
     *
     * @param  list<string>  $certificates
     * @return list<string>
     */
    private static function sortedFingerprints(array $certificates): array
    {
        $fingerprints = array_map(self::fingerprintOf(...), $certificates);

        sort($fingerprints);

        return $fingerprints;
    }

    /**
     * The fingerprint of the certificate.
     *
     * @param  string  $certificate
     * @return string
     */
    private static function fingerprintOf(string $certificate): string
    {
        return (string) openssl_x509_fingerprint($certificate, 'sha256');
    }

    /**
     * The key helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyService
     */
    private function keys(): KeyService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyService::class);
    }

    /**
     * The key ring, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyRing
     */
    private function ring(): KeyRing
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyRing::class);
    }

    /**
     * The summary the result carries, which it must.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyResult  $result
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private static function summaryOf(KeyResult $result): KeySummary
    {
        self::assertNotNull($result->key, sprintf('The helper answered %s (%s).', $result->status->value, $result->reason->value ?? 'no reason'));

        return $result->key;
    }
}
