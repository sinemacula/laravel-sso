<?php

declare(strict_types = 1);

namespace Tests\Feature\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Results\ExampleResults;
use Tests\TestCase;

/**
 * Feature tests for the package's own handoff store (SSO-9.2, SSO-9.10,
 * SSO-11.9): the row an issued code is stored as, every column pinned; only the
 * code's digest kept, never the code; the verified result encrypted and
 * restored exactly; the expiry kept to the second and answered as stored; a new
 * code for every issue; and nothing kept when the completion's transaction
 * rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseHandoffStore::class)]
final class DatabaseHandoffStoreTest extends TestCase
{
    use UsesFlowTables;

    /** @var string The connection every example result names. */
    private const string CONNECTION_ID = '01jbexampleconnection00000';

    /** @var string The S256 challenge of the client's verifier. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * Bind a fixed clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->createFlowTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropFlowTables();

        parent::tearDown();
    }

    /**
     * The package's store is the default handoff issuer.
     *
     * @return void
     */
    public function testItIsTheDefaultIssuer(): void
    {
        self::assertInstanceOf(DatabaseHandoffStore::class, $this->app?->make(HandoffIssuer::class));
    }

    /**
     * A `reauthenticate` grant is stored as one row holding what the code is
     * bound to, the enforcement version, the session's latest end and the
     * expiry, stamped now and neither redeemed nor voided.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheStoredRowIsPinned(): void
    {
        $issued = $this->store()->issue(new HandoffGrant(
            result: ExampleResults::full(Purpose::REAUTHENTICATE, self::CONNECTION_ID),
            challenge: S256Challenge::fromString(self::CHALLENGE),
            expiresAt: CarbonImmutable::parse('2026-11-01T09:31:00Z'),
            linkedIdentity: new IdentityReference('App\Models\User', '42'),
            identity: new IdentityReference('App\Models\Member', '7'),
            sessionId: 'session-1',
            enforcementVersion: 'version-1',
            sessionNotAfter: CarbonImmutable::parse('2026-11-01T18:00:00Z'),
        ));

        $row = StoredCode::query()->sole();

        self::assertSame([
            'code_digest'          => hash('sha256', $issued->code->reveal()),
            'purpose'              => 'reauthenticate',
            'application'          => 'web',
            'connection_id'        => self::CONNECTION_ID,
            'request_reference'    => ExampleResults::REFERENCE,
            'handoff_challenge'    => self::CHALLENGE,
            'identity_type'        => 'App\Models\Member',
            'identity_id'          => '7',
            'session_id'           => 'session-1',
            'linked_identity_type' => 'App\Models\User',
            'linked_identity_id'   => '42',
            'enforcement_version'  => 'version-1',
            'session_not_after'    => '2026-11-01T18:00:00+00:00',
            'expires_at'           => '2026-11-01T09:31:00+00:00',
            'redeemed_at'          => null,
            'voided_at'            => null,
            'created_at'           => '2026-11-01T09:30:00+00:00',
            'updated_at'           => '2026-11-01T09:30:00+00:00',
        ], [
            'code_digest'          => $row->code_digest,
            'purpose'              => $row->purpose->value,
            'application'          => $row->application,
            'connection_id'        => $row->connection_id,
            'request_reference'    => $row->request_reference,
            'handoff_challenge'    => $row->handoff_challenge,
            'identity_type'        => $row->identity_type,
            'identity_id'          => $row->identity_id,
            'session_id'           => $row->session_id,
            'linked_identity_type' => $row->linked_identity_type,
            'linked_identity_id'   => $row->linked_identity_id,
            'enforcement_version'  => $row->enforcement_version,
            'session_not_after'    => $row->session_not_after?->toIso8601String(),
            'expires_at'           => $row->expires_at->toIso8601String(),
            'redeemed_at'          => $row->redeemed_at,
            'voided_at'            => $row->voided_at,
            'created_at'           => $row->created_at->toIso8601String(),
            'updated_at'           => $row->updated_at->toIso8601String(),
        ]);
        self::assertSame('2026-11-01T09:31:00+00:00', $issued->expiresAt->toIso8601String());
        self::assertMatchesRegularExpression('/^[0-9a-z]{26}$/', $row->id);
    }

    /**
     * A `sign_in` grant linked to nothing stores no identity, no session, no
     * linked identity, no version and no session end.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASignInGrantStoresNoIdentityOrSession(): void
    {
        $this->store()->issue(new HandoffGrant(
            result: ExampleResults::bare(Purpose::SIGN_IN, self::CONNECTION_ID),
            challenge: S256Challenge::fromString(self::CHALLENGE),
            expiresAt: CarbonImmutable::parse('2026-11-01T09:31:00Z'),
        ));

        $row = StoredCode::query()->sole();

        self::assertSame('sign_in', $row->purpose->value);
        self::assertSame(
            [null, null, null, null, null, null, null],
            [$row->identity_type, $row->identity_id, $row->session_id, $row->linked_identity_type, $row->linked_identity_id, $row->enforcement_version, $row->session_not_after],
        );
    }

    /**
     * Only the code's digest is stored: the code is in no column, and the
     * digest is its lower-case hex SHA-256, which it matches.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOnlyTheDigestIsStored(): void
    {
        $issued = $this->issue();
        $code   = $issued->code->reveal();
        $row    = (array) DB::table(StorageConnection::table('handoff_codes.table'))->sole();

        self::assertTrue(HandoffCode::isWellFormed($code));
        self::assertSame(hash('sha256', $code), $row['code_digest']);
        self::assertTrue($issued->code->matches($row['code_digest']));

        foreach ($row as $column => $value) {
            self::assertStringNotContainsString($code, (string) $value, "The code is stored in [{$column}].");
        }
    }

    /**
     * The verified result is stored encrypted: no column shows its subject or
     * an attribute, and decrypted it is the JSON of its stored form, which
     * restores the result exactly.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheResultIsEncryptedAndRestoresExactly(): void
    {
        $result = ExampleResults::full(Purpose::SIGN_IN, self::CONNECTION_ID);

        $this->issue($result);

        $row = (array) DB::table(StorageConnection::table('handoff_codes.table'))->sole();

        foreach ($row as $column => $value) {
            foreach (['Subject 1', 'person@example.com', 'admins', 'session-index-1'] as $needle) {
                self::assertStringNotContainsString($needle, (string) $value, "The result is readable in [{$column}].");
            }
        }

        $json = app(SecretEncrypter::class)->decrypt((string) $row['result']);

        self::assertSame((string) json_encode($result->toArray()), $json);

        /** @var array<string, mixed> $stored */
        $stored = json_decode($json, true);

        self::assertSame($result->toArray(), VerifiedResult::restore($stored)->toArray());
    }

    /**
     * The expiry is kept to the whole second, and the issued handoff answers it
     * as stored.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheExpiryIsKeptToTheSecond(): void
    {
        $issued = $this->issue(expiresAt: CarbonImmutable::parse('2026-11-01T09:31:05.900Z'));

        self::assertSame('2026-11-01T09:31:05.000000Z', $issued->expiresAt->toIso8601ZuluString('microsecond'));
        self::assertSame('2026-11-01T09:31:05+00:00', StoredCode::query()->sole()->expires_at->toIso8601String());
    }

    /**
     * Each issue stores a new code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachIssueStoresANewCode(): void
    {
        $first  = $this->issue()->code->reveal();
        $second = $this->issue()->code->reveal();

        self::assertNotSame($first, $second);
        self::assertSame(2, StoredCode::query()->count());

        $stored   = StoredCode::query()->pluck('code_digest')->all();
        $expected = [hash('sha256', $first), hash('sha256', $second)];

        sort($stored);
        sort($expected);

        self::assertSame($expected, $stored);
    }

    /**
     * Issued inside the completion's transaction, a code is kept only when it
     * commits: a rollback keeps nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeIssuedInATransactionRolledBackIsNotKept(): void
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        $this->issue();

        self::assertSame(1, StoredCode::query()->count());

        $database->rollBack();

        self::assertSame(0, StoredCode::query()->count());
    }

    /**
     * Issue a code for the result, a `sign_in` through the example connection
     * by default, expiring a minute from now unless given.
     *
     * @param  ?\SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @return \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff
     *
     * @throws \Random\RandomException
     */
    private function issue(?VerifiedResult $result = null, ?CarbonImmutable $expiresAt = null): IssuedHandoff
    {
        return $this->store()->issue(new HandoffGrant(
            result: $result ?? ExampleResults::bare(Purpose::SIGN_IN, self::CONNECTION_ID),
            challenge: S256Challenge::fromString(self::CHALLENGE),
            expiresAt: $expiresAt ?? CarbonImmutable::parse('2026-11-01T09:31:00Z'),
            linkedIdentity: new IdentityReference('App\Models\User', '42'),
        ));
    }

    /**
     * The package's store, resolved from the container.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore
     */
    private function store(): DatabaseHandoffStore
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DatabaseHandoffStore::class);
    }
}
