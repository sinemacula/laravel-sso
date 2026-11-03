<?php

declare(strict_types = 1);

namespace Tests\Feature\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffEvents;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Linking\AllowingLinkEligibility;
use Tests\Fixtures\Linking\RecordingSessions;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Pins what a redemption reports (SSO-10.1, SSO-10.2, SSO-10.4, SSO-9.8): a
 * redeemed code is `[HandoffRedeemed]`, and every refusal exactly one
 * `FlowFailed` for the redemption flow with its reason, each with its whole
 * context: before a code is found, the purpose asked; once found, the code's
 * connection, application, purpose, reference and identity (the flow's for a
 * `link` or `reauthenticate`, the linked one otherwise) and the session of a
 * `reauthenticate`; once the connection's row is read, its tenant and protocol.
 * No event carries the code, its digest, the verifier, the challenge, the
 * subject or an attribute.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
#[CoversClass(HandoffEvents::class)]
final class RedemptionEventSequenceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The shipped migration of the single-use keys. */
    private const string SINGLE_USE_MIGRATION = '/database/migrations/2026_10_31_000000_create_sso_single_use_keys_table.php';

    /** @var string The shipped migration of the rate limit counters. */
    private const string RATE_LIMITS_MIGRATION = '/database/migrations/2026_10_31_000001_create_sso_rate_limits_table.php';

    /** @var string When every event occurs. */
    private const string OCCURRED_AT = '2026-11-01T09:30:00.000000Z';

    /** @var string The client's IP address. */
    private const string IP = '203.0.113.7';

    /** @var string The client's user agent. */
    private const string USER_AGENT = 'ExampleBrowser/1.0';

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The S256 challenge of the client's verifier. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var string The request's public reference every code carries. */
    private const string REFERENCE = 'Fq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection the codes are issued through. */
    private Connection $connection;

    /** @var ?\SineMacula\Laravel\Sso\Identities\IdentityReference What every result is linked to, at issuance and now. */
    private ?IdentityReference $linked = null;

    /**
     * Bind a fixed clock, a linker answering the linked identity and a request
     * from a client, register the driver, create the tables and a usable
     * connection, and start recording events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $resolve = fn (): ?IdentityReference => $this->linked;

        $this->clock  = new FixedClock('2026-11-01T09:30:00Z');
        $this->linked = new IdentityReference('App\Models\User', '42');

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Linker::class, new readonly class ($resolve) implements Linker {
            /**
             * Constructor.
             *
             * @param  \Closure(): ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
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
                unset($result);

                return ExampleLinks::resolution(($this->resolve)());
            }
        });
        $this->app?->instance('request', Request::create('/auth/sso/handoffs', 'POST', server: [
            'REMOTE_ADDR'     => self::IP,
            'HTTP_USER_AGENT' => self::USER_AGENT,
        ]));

        $driver = new VerifyingDriver;

        config()->set('sso.features.oidc', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->createConnectionTables();
        $this->createFlowTables();
        self::migration(self::SINGLE_USE_MIGRATION)->up(); // @phpstan-ignore method.notFound
        self::migration(self::RATE_LIMITS_MIGRATION)->up(); // @phpstan-ignore method.notFound

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);

        $this->startRecordingEvents();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::migration(self::RATE_LIMITS_MIGRATION)->down(); // @phpstan-ignore method.notFound
        self::migration(self::SINGLE_USE_MIGRATION)->down(); // @phpstan-ignore method.notFound
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A redeemed `sign_in` reports `HandoffRedeemed` alone, naming the
     * connection, its tenant and protocol, the application, the purpose, the
     * reference and the identity its link resolved to.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedeemedSignInReportsHandoffRedeemed(): void
    {
        self::assertTrue($this->redeem($this->issue())->isRedeemed());

        $this->assertEventSequence([HandoffRedeemed::class]);
        $this->assertNoFailure();

        self::assertSame([$this->context($this->codeFields())], $this->contexts());
    }

    /**
     * A redeemed `link` names the identity the flow was started for, and a
     * redeemed `reauthenticate` that identity and its session.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedeemedLinkOrReauthenticateNamesTheFlowsIdentity(): void
    {
        $this->readyForTheFlowsIdentity();

        $this->redeem($this->issue(Purpose::LINK), purpose: Purpose::LINK);
        $this->redeem($this->issue(Purpose::REAUTHENTICATE), purpose: Purpose::REAUTHENTICATE);

        $this->assertEventSequence([HandoffRedeemed::class, HandoffRedeemed::class, ReauthenticationCompleted::class]);

        self::assertSame([
            $this->context(['purpose' => 'link', 'identity_id' => '7'] + $this->codeFields()),
            $this->context(['purpose' => 'reauthenticate', 'identity_id' => '7', 'session_id' => 'session-1'] + $this->codeFields()),
            $this->context(['purpose' => 'reauthenticate', 'identity_id' => '7', 'session_id' => 'session-1'] + $this->codeFields()),
        ], $this->contexts());
    }

    /**
     * A redeemed unlinked handoff names no identity.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedeemedUnlinkedHandoffNamesNoIdentity(): void
    {
        $this->linked = null;

        $this->redeem($this->issue());

        $this->assertEventSequence([HandoffRedeemed::class]);

        self::assertSame([$this->context(['identity_morph_class' => null, 'identity_id' => null] + $this->codeFields())], $this->contexts());
    }

    /**
     * Each refusal of a code found, and its reason.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function refusals(): iterable
    {
        yield 'voided' => ['voided', FailureReason::HANDOFF_UNKNOWN];
        yield 'replayed' => ['replayed', FailureReason::REPLAYED];
        yield 'expired' => ['expired', FailureReason::HANDOFF_EXPIRED];
        yield 'another purpose' => ['another purpose', FailureReason::PURPOSE_MISMATCH];
        yield 'another application' => ['another application', FailureReason::APPLICATION_MISMATCH];
        yield 'another connection' => ['another connection', FailureReason::CONNECTION_MISMATCH];
        yield 'another verifier' => ['another verifier', FailureReason::VERIFIER_MISMATCH];
        yield 'disabled' => ['disabled', FailureReason::CONNECTION_UNAVAILABLE];
        yield 'enforcement' => ['enforcement', FailureReason::ENFORCEMENT_UNSATISFIED];
        yield 'link changed' => ['link changed', FailureReason::LINK_CHANGED];
    }

    /**
     * Every refusal reports exactly one `FlowFailed` for the redemption, with
     * its reason, and nothing else; the purpose reported once a code is found
     * is the code's, whatever was asked.
     *
     * @param  string  $scenario
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('refusals')]
    public function testEveryRefusalReportsExactlyOneFailure(string $scenario, FailureReason $reason): void
    {
        $answer = $this->refuse($scenario);

        self::assertSame($reason, $answer->reason);

        $this->assertEventSequence([FlowFailed::class]);
        $this->assertExactlyOneFailure(Flow::REDEMPTION, $reason);

        self::assertSame([$this->context($this->codeFields())], $this->contexts());
    }

    /**
     * A refusal before a code is found names only the purpose asked: a full
     * limit and a code that names none.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusalBeforeACodeIsFoundNamesOnlyThePurposeAsked(): void
    {
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->redeem(str_repeat('A', 43), purpose: Purpose::REAUTHENTICATE)->reason);

        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::HANDOFF_UNKNOWN);

        self::assertSame([$this->context(['purpose' => 'reauthenticate'])], $this->contexts());

        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $this->startRecordingEvents();

        self::assertTrue($this->redeem($this->issue(), purpose: Purpose::LINK)->isRateLimited());

        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::RATE_LIMITED);

        self::assertSame([$this->context(['purpose' => 'link'])], $this->contexts());
    }

    /**
     * A code whose connection is gone names the code's connection, and no
     * tenant or protocol.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeWhoseConnectionIsGoneNamesNoTenant(): void
    {
        $code = $this->issue();

        $this->connection->delete();

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->redeem($code)->reason);

        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::CONNECTION_UNAVAILABLE);

        self::assertSame([$this->context(['connection_tenant_id' => null, 'protocol' => null] + $this->codeFields())], $this->contexts());
    }

    /**
     * A code whose row is gone once its connection is locked, though the
     * connection is still there, is `handoff_unknown`, reported with the code's
     * connection, its tenant and protocol; nothing is consumed or recorded.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeGoneOnceItsConnectionIsLockedNamesTheConnection(): void
    {
        $code     = $this->issue();
        $database = DB::connection(StorageConnection::name());
        $table    = (new Connection)->getTable();
        $deleted  = false;

        $database->listen(static function (QueryExecuted $query) use ($database, $table, &$deleted): void {

            $sql = strtolower($query->sql);

            if ($deleted || $database->transactionLevel() === 0 || !str_starts_with($sql, 'select') || !str_contains($sql, $table)) {
                return;
            }

            $deleted = true;

            $database->table(StorageConnection::table('handoff_codes.table'))->delete();
        });

        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->redeem($code)->reason);
        self::assertTrue($deleted);

        $this->assertExactlyOneFailure(Flow::REDEMPTION, FailureReason::HANDOFF_UNKNOWN);

        self::assertSame([$this->context($this->codeFields())], $this->contexts());
        self::assertSame(0, StoredCode::query()->count());
        self::assertSame(0, $database->table(StorageConnection::table('single_use.table'))->count());
    }

    /**
     * No event carries the code, its digest, the verifier, the challenge, the
     * subject or an attribute, and each holds only its context, and a failure's
     * flow and reason.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNoEventCarriesASecretOrTheResult(): void
    {
        $code     = $this->issue();
        $refused  = $this->issue();
        $verifier = 'another-clients-verifier-of-43-characters-0';

        $this->redeem($code);
        $this->redeem($refused, $verifier);

        $this->assertEventSequence([HandoffRedeemed::class, FlowFailed::class]);

        $shown = (string) json_encode($this->contexts());

        $secrets = [
            $code,
            hash('sha256', $code),
            $refused,
            hash('sha256', $refused),
            self::VERIFIER,
            $verifier,
            self::CHALLENGE,
            VerifyingDriver::SUBJECT,
            'person@example.com',
            'staff',
        ];

        foreach ($secrets as $secret) {
            self::assertStringNotContainsString($secret, $shown);
            self::assertStringNotContainsString($secret, serialize($this->recordedEvents()));
        }

        self::assertSame(['context'], array_keys(get_object_vars($this->recordedEvents()[0])));
        self::assertSame(['context', 'flow', 'reason'], array_keys(get_object_vars($this->recordedEvents()[1])));
    }

    /**
     * Set the scenario up and redeem in it.
     *
     * @param  string  $scenario
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     *
     * @throws \Random\RandomException
     */
    private function refuse(string $scenario): RedemptionResult
    {
        $code = $this->issue(expiresAt: $scenario === 'expired' ? $this->clock->now() : null);

        $this->arrangeScenario($scenario, StoredCode::query()->where('code_digest', hash('sha256', $code))->sole());

        return match ($scenario) {
            'another purpose'     => $this->redeem($code, purpose: Purpose::LINK),
            'another application' => $this->redeem($code, application: 'mobile'),
            'another connection'  => $this->redeem($code, connectionId: '01jbz0000000000000000000zz'),
            'another verifier'    => $this->redeem($code, 'another-clients-verifier-of-43-characters-0'),
            default               => $this->redeem($code),
        };
    }

    /**
     * Change what the scenario changes since the code was issued.
     *
     * @param  string  $scenario
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $row
     * @return void
     */
    private function arrangeScenario(string $scenario, StoredCode $row): void
    {
        match ($scenario) {
            'voided'       => $row->forceFill(['voided_at' => $this->clock->now()])->save(),
            'replayed'     => $row->forceFill(['redeemed_at' => $this->clock->now()])->save(),
            'disabled'     => $this->connection->forceFill(['enabled' => false])->save(),
            'link changed' => $this->linked = new IdentityReference('App\Models\User', '43'),
            'enforcement'  => $this->app?->instance(Enforcement::class, $this->requiring('01jbz0000000000000000000zz')),
            default        => null,
        };
    }

    /**
     * An enforcement contract requiring sign-in through the connection given.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Contracts\Enforcement
     */
    private function requiring(string $connectionId): Enforcement
    {
        return new readonly class ($connectionId) implements Enforcement {
            /**
             * Constructor.
             *
             * @param  string  $connectionId
             */
            public function __construct(

                /** The connection the enforcement requires. */
                private string $connectionId,
            ) {}

            /**
             * A policy requiring the connection.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
             */
            #[\Override]
            public function policy(string $tenantId, string $application): EnforcementPolicy
            {
                unset($application);

                return EnforcementPolicy::required($tenantId, $tenantId, [$this->connectionId], 'version-2');
            }
        };
    }

    /**
     * Issue a code through the package's store for the purpose, linked to the
     * identity the test holds, expiring a minute from now unless given.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issue(Purpose $purpose = Purpose::SIGN_IN, ?CarbonImmutable $expiresAt = null): string
    {
        $result = new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: $purpose,
            requestReference: RequestReference::fromString(self::REFERENCE),
            attributes: ['email' => 'person@example.com', 'groups' => ['staff']],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext(CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd']),
        );

        $grant = new HandoffGrant(
            result: $result,
            challenge: S256Challenge::fromString(self::CHALLENGE),
            expiresAt: $expiresAt ?? $this->clock->now()->addMinute(),
            linkedIdentity: $this->linked,
            identity: $purpose    === Purpose::SIGN_IN ? null : new IdentityReference('App\Models\User', '7'),
            sessionId: $purpose   === Purpose::REAUTHENTICATE ? 'session-1' : null,
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
     * What a `sign_in` code found through the connection is reported with.
     *
     * @return array<string, ?string>
     */
    private function codeFields(): array
    {
        return [
            'connection_id'        => $this->connection->id,
            'connection_tenant_id' => 'tenant-1',
            'protocol'             => VerifyingDriver::NAME,
            'application'          => 'web',
            'purpose'              => 'sign_in',
            'request_reference'    => self::REFERENCE,
            'identity_morph_class' => 'App\Models\User',
            'identity_id'          => '42',
        ];
    }

    /**
     * The contexts of the events recorded, in order.
     *
     * @return list<array<string, ?string>>
     */
    private function contexts(): array
    {
        return array_map(static fn (SsoEvent $event): array => $event->context()->toArray(), $this->recordedEvents());
    }

    /**
     * The whole context an event carries: the time and the client, the fields
     * given, and `null` for every other.
     *
     * @param  array<string, ?string>  $fields
     * @return array<string, ?string>
     */
    private function context(array $fields): array
    {
        return array_merge([
            'occurred_at'                 => self::OCCURRED_AT,
            'ip'                          => self::IP,
            'user_agent'                  => self::USER_AGENT,
            'connection_id'               => null,
            'connection_tenant_id'        => null,
            'protocol'                    => null,
            'application'                 => null,
            'purpose'                     => null,
            'request_reference'           => null,
            'identity_morph_class'        => null,
            'identity_id'                 => null,
            'acting_identity_morph_class' => null,
            'acting_identity_id'          => null,
            'principal_morph_class'       => null,
            'principal_id'                => null,
            'tenant_id'                   => null,
            'session_id'                  => null,
            'method'                      => null,
        ], $fields);
    }

    /**
     * The shipped migration of the file.
     *
     * @param  string  $file
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function migration(string $file): Migration
    {
        return require dirname(__DIR__, 3) . $file;
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
