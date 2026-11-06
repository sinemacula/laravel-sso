<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for the voiding a trust change makes (SSO-2.13): the requests
 * and handoff codes of the connection before and after each change. Every
 * change that asks `sso.connection.trust` (an update of a trust setting or
 * secret, trusting or distrusting a certificate) voids the connection's
 * unfinished requests, consumed ones included, and unredeemed codes, keeps the
 * first `voided_at` of one voided before, and leaves finished requests,
 * redeemed codes and every other connection's rows as they are. A change that
 * asks another operation or none (the display name, the scopes, the mapping,
 * IdP-initiated sign-in), a refused change, and the rotation of a key of the
 * service provider's own void nothing. Rotating a credential (a client secret,
 * a trusted certificate, a key of the service provider's own) is allowed on a
 * connection with an active link, which only a change to what subjects mean
 * refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InFlightVoider::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(KeyService::class)]
final class TrustChangeVoidingTest extends TestCase
{
    use UsesFlowTables;

    /** @var string The tenant the connections belong to. */
    private const string TENANT = 'tenant-1';

    /** @var string When the change voids what is in flight, a minute after the rows were made. */
    private const string VOIDED = '2026-11-01T09:31:00+00:00';

    /** @var string When a request or code was voided before the change. */
    private const string EARLIER = '2026-11-01T09:00:00+00:00';

    /** @var array<string, string> The settings of a complete OIDC connection, with its client secret. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
        'client_secret'          => 'the-client-secret-value',
    ];

    /** @var array<string, string> The settings of a complete SAML connection. */
    private const array SAML = [
        'idp_entity_id' => 'https://idp.example.com/entity',
        'sso_url'       => 'https://idp.example.com/sso',
    ];

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helpers ask. */
    private RecordingFreshness $freshness;

    /**
     * Bind a fixed clock and a fresh freshness contract, turn both protocols
     * and IdP-initiated sign-in on, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->freshness = new RecordingFreshness;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.mapping.custom_attributes', ['department']);

        $this->usePackageTables();
    }

    /**
     * A trust change voids the connection's pending and consumed but unfinished
     * requests and its unredeemed codes, stamped with the clock's now; a
     * finished request, a redeemed code, one voided before (which keeps its
     * first stamp) and another connection's rows are left as they are.
     *
     * @return void
     */
    public function testATrustChangeVoidsOnlyWhatIsInFlight(): void
    {
        $connection = $this->oidc();
        $other      = $this->oidc();
        $rows       = $this->populate($connection);
        $others     = $this->populate($other);

        $this->clock->advance(60);

        $result = $this->connections()->update(self::TENANT, $connection->id, ['settings' => ['token_endpoint' => 'https://idp.example.com/oauth2/token']]);

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame([
            $rows['pending']    => self::VOIDED,
            $rows['consumed']   => self::VOIDED,
            $rows['finished']   => null,
            $rows['voided']     => self::EARLIER,
            $others['pending']  => null,
            $others['consumed'] => null,
            $others['finished'] => null,
            $others['voided']   => self::EARLIER,
        ], self::requestsVoided());
        self::assertSame([
            $rows['unredeemed']   => self::VOIDED,
            $rows['redeemed']     => null,
            $rows['voidedCode']   => self::EARLIER,
            $others['unredeemed'] => null,
            $others['redeemed']   => null,
            $others['voidedCode'] => self::EARLIER,
        ], self::codesVoided());
        self::assertSame(self::VOIDED, AuthorizationRequest::query()->findOrFail($rows['pending'])->updated_at->toIso8601String());
        self::assertSame(self::VOIDED, HandoffCode::query()->findOrFail($rows['unredeemed'])->updated_at->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', AuthorizationRequest::query()->findOrFail($rows['finished'])->updated_at->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', HandoffCode::query()->findOrFail($rows['redeemed'])->updated_at->toIso8601String());
    }

    /**
     * Rows of `[changes]`: each update that asks `sso.connection.trust`.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideTrustChanges(): iterable
    {
        yield from [
            'an endpoint'           => [['settings' => ['jwks_uri' => 'https://idp.example.com/keys']]],
            'the issuer'            => [['settings' => ['issuer' => 'https://login.example.com']]],
            'the client id'         => [['settings' => ['client_id' => 'client-456']]],
            'the client secret'     => [['settings' => ['client_secret' => 'a-rotated-client-secret']]],
            'the algorithms'        => [['settings' => ['id_token_algorithms' => ['ES256']]]],
            'with the display name' => [['display_name' => 'Renamed', 'settings' => ['returns_iss' => true]]],
        ];
    }

    /**
     * Each update that asks `sso.connection.trust` voids what is in flight.
     *
     * @param  array<string, mixed>  $changes
     * @return void
     */
    #[DataProvider('provideTrustChanges')]
    public function testEachTrustChangeVoids(array $changes): void
    {
        $connection = $this->oidc();
        $rows       = $this->populate($connection);

        $this->clock->advance(60);

        self::assertSame(ConnectionStatus::UPDATED, $this->connections()->update(self::TENANT, $connection->id, $changes)->status);

        $this->assertVoided($rows);
    }

    /**
     * Rows of `[protocol, changes]`: each update that asks something else than
     * `sso.connection.trust`, or nothing.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>}>
     */
    public static function provideOtherChanges(): iterable
    {
        yield from [
            'the display name'      => ['oidc', ['display_name' => 'Renamed']],
            'the scopes'            => ['oidc', ['settings' => ['scopes' => ['openid', 'email']]]],
            'the extra parameters'  => ['oidc', ['settings' => ['extra_parameters' => ['prompt' => 'login']]]],
            'the mapping'           => ['oidc', ['attribute_mapping' => ['department' => 'dept']]],
            'a request option'      => ['saml2', ['settings' => ['force_authn' => true]]],
            'idp-initiated sign-in' => ['saml2', ['settings' => ['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/sso/start']]],
        ];
    }

    /**
     * An update that asks another operation than `sso.connection.trust`, or
     * none, voids nothing.
     *
     * @param  string  $protocol
     * @param  array<string, mixed>  $changes
     * @return void
     */
    #[DataProvider('provideOtherChanges')]
    public function testAnyOtherChangeVoidsNothing(string $protocol, array $changes): void
    {
        $connection = $protocol === 'oidc' ? $this->oidc() : $this->saml();
        $rows       = $this->populate($connection);

        $this->clock->advance(60);

        self::assertSame(ConnectionStatus::UPDATED, $this->connections()->update(self::TENANT, $connection->id, $changes)->status);

        $this->assertNotVoided($rows);
    }

    /**
     * A trust change that is stale, invalid or changes nothing voids nothing.
     *
     * @return void
     */
    public function testARefusedOrUnchangedTrustChangeVoidsNothing(): void
    {
        $connection = $this->oidc();
        $rows       = $this->populate($connection);

        $endpoint = static fn (string $url): array => ['settings' => ['token_endpoint' => $url]];

        self::assertSame(ConnectionStatus::INVALID, $this->connections()->update(self::TENANT, $connection->id, $endpoint('http://idp.example.com/token'))->status);
        self::assertSame(ConnectionStatus::UNCHANGED, $this->connections()->update(self::TENANT, $connection->id, $endpoint(self::OIDC['token_endpoint']))->status);

        $this->freshness->answer(FreshnessOutcome::STALE);

        self::assertSame(ConnectionStatus::REFUSED, $this->connections()->update(self::TENANT, $connection->id, $endpoint('https://idp.example.com/oauth2/token'))->status);

        $this->assertNotVoided($rows);
    }

    /**
     * Rotating a key of the service provider's own keeps what subjects mean:
     * adding, making current and retiring one void nothing.
     *
     * @return void
     */
    public function testRotatingAnOwnKeyVoidsNothing(): void
    {
        $connection = $this->saml();
        $rows       = $this->populate($connection);

        $this->clock->advance(60);

        $current = self::keyOf($this->keys()->addNext(self::TENANT, $connection->id, KeyUse::SP_SIGNING, KeyType::RSA));
        $next    = self::keyOf($this->keys()->addNext(self::TENANT, $connection->id, KeyUse::SP_SIGNING, KeyType::RSA));

        self::assertTrue($this->keys()->makeCurrent(self::TENANT, $connection->id, $next)->isSucceeded());
        self::assertTrue($this->keys()->retire(self::TENANT, $connection->id, $current)->isSucceeded());

        $this->assertNotVoided($rows);
    }

    /**
     * Trusting a signing certificate is additive and voids nothing; trusting a
     * metadata signing anchor, and distrusting a certificate, each void what is
     * in flight.
     *
     * @return void
     */
    public function testTrustingAnAnchorAndDistrustingACertificateVoid(): void
    {
        $connection = $this->saml();
        $rows       = $this->populate($connection);

        $this->clock->advance(60);

        $certificate = self::keyOf($this->keys()->trustCertificate(self::TENANT, $connection->id, Certificates::distinct(0)));

        $this->assertNotVoided($rows);

        self::assertTrue($this->keys()->trustCertificate(self::TENANT, $connection->id, Certificates::distinct(1), null, KeyUse::METADATA_SIGNING)->isSucceeded());

        $this->assertVoided($rows);

        $later = $this->populate($connection);

        $this->clock->advance(60);

        self::assertTrue($this->keys()->distrustCertificate(self::TENANT, $connection->id, $certificate)->isSucceeded());

        self::assertSame('2026-11-01T09:32:00+00:00', AuthorizationRequest::query()->findOrFail($later['pending'])->voided_at?->toIso8601String());
        self::assertSame('2026-11-01T09:32:00+00:00', HandoffCode::query()->findOrFail($later['unredeemed'])->voided_at?->toIso8601String());
        self::assertSame(self::VOIDED, AuthorizationRequest::query()->findOrFail($rows['pending'])->voided_at?->toIso8601String());
    }

    /**
     * Rotating a credential alters no subject, so a connection with an active
     * link allows it: a client secret, a trusted certificate trusted and then
     * distrusted, and a key of the service provider's own added, made current
     * and retired, each succeed and keep the link; changing the issuer of the
     * same connection is refused with `connection_has_links`.
     *
     * @return void
     */
    public function testRotatingACredentialIsAllowedWithLinks(): void
    {
        $oidc = $this->oidc();
        $saml = $this->saml();
        $keys = $this->keys();

        $this->makeLink($oidc);
        $this->makeLink($saml, 'subject-2');

        self::assertSame(ConnectionStatus::UPDATED, $this->connections()->update(self::TENANT, $oidc->id, ['settings' => ['client_secret' => 'a-rotated-client-secret']])->status);
        $issuer = $this->connections()->update(self::TENANT, $oidc->id, ['settings' => ['issuer' => 'https://login.example.com']]);

        self::assertSame(FailureReason::CONNECTION_HAS_LINKS, $issuer->reason);

        $certificate = self::keyOf($keys->trustCertificate(self::TENANT, $saml->id, Certificates::distinct(0)));
        $current     = self::keyOf($keys->addNext(self::TENANT, $saml->id, KeyUse::SP_SIGNING, KeyType::RSA));
        $next        = self::keyOf($keys->addNext(self::TENANT, $saml->id, KeyUse::SP_SIGNING, KeyType::RSA));

        self::assertTrue($keys->makeCurrent(self::TENANT, $saml->id, $next)->isSucceeded());
        self::assertTrue($keys->retire(self::TENANT, $saml->id, $current)->isSucceeded());
        self::assertTrue($keys->distrustCertificate(self::TENANT, $saml->id, $certificate)->isSucceeded());
        self::assertSame(2, Link::query()->where('state', 'active')->count());
    }

    /**
     * A refused certificate change voids nothing.
     *
     * @return void
     */
    public function testARefusedCertificateChangeVoidsNothing(): void
    {
        $connection = $this->saml();
        $rows       = $this->populate($connection);

        self::assertTrue($this->keys()->trustCertificate(self::TENANT, $connection->id, 'not a certificate')->isInvalid());

        $this->freshness->answer(FreshnessOutcome::STALE);

        self::assertTrue($this->keys()->trustCertificate(self::TENANT, $connection->id, Certificates::distinct(0))->isRefused());

        $this->assertNotVoided($rows);
    }

    /**
     * The voider calls the seam that voids open link reservations once, with
     * the locked connection, inside the transaction, after the requests and
     * codes are voided.
     *
     * @return void
     */
    public function testVoidsTheReservationsLast(): void
    {
        /** @var \ArrayObject<int, array{0: string, 1: int, 2: int, 3: int}> $seen */
        $seen = new \ArrayObject;

        $this->app?->instance(InFlightVoider::class, new readonly class ($this->clock, $seen) extends InFlightVoider {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
             * @param  \ArrayObject<int, array{0: string, 1: int, 2: int, 3: int}>  $seen
             */
            public function __construct(

                // The clock the voids are stamped from, handed to the parent,
                // which holds it
                Clock $clock,

                /** What each call to the seam saw. */
                private \ArrayObject $seen,
            ) {
                parent::__construct($clock);
            }

            /**
             * Record the connection, what is still unvoided and the transaction
             * level.
             *
             * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
             * @return void
             */
            #[\Override]
            protected function reservationsVoided(Connection $locked): void
            {
                $this->seen->append([
                    $locked->id,
                    AuthorizationRequest::query()->whereNull('voided_at')->whereNull('completed_at')->count(),
                    HandoffCode::query()->whereNull('voided_at')->whereNull('redeemed_at')->count(),
                    DB::connection(StorageConnection::name())->transactionLevel(),
                ]);
            }
        });

        $connection = $this->oidc();

        $this->populate($connection);

        $this->connections()->update(self::TENANT, $connection->id, ['settings' => ['client_id' => 'client-456']]);

        self::assertSame([[$connection->id, 0, 0, 1]], $seen->getArrayCopy());
    }

    /**
     * Voiding outside a transaction on the storage connection is the caller's
     * mistake, and voids nothing.
     *
     * @return void
     */
    public function testRefusesToVoidOutsideATransaction(): void
    {
        $connection = $this->oidc();
        $rows       = $this->populate($connection);

        try {
            app(InFlightVoider::class)->voidFor($connection);
            self::fail('A void outside a transaction was made.');
        } catch (\LogicException $exception) {
            self::assertSame('In-flight flows are voided inside the transaction that changes their connection.', $exception->getMessage());
        }

        $this->assertNotVoided($rows);
    }

    /**
     * Assert the pending and consumed requests and the unredeemed code were
     * voided by the change, and the rest left as they were.
     *
     * @param  array<string, string>  $rows
     * @return void
     */
    private function assertVoided(array $rows): void
    {
        self::assertSame(
            [self::VOIDED, self::VOIDED, null, self::EARLIER],
            self::voidedAt(AuthorizationRequest::class, [$rows['pending'], $rows['consumed'], $rows['finished'], $rows['voided']]),
        );
        self::assertSame(
            [self::VOIDED, null, self::EARLIER],
            self::voidedAt(HandoffCode::class, [$rows['unredeemed'], $rows['redeemed'], $rows['voidedCode']]),
        );
    }

    /**
     * Assert the change voided nothing.
     *
     * @param  array<string, string>  $rows
     * @return void
     */
    private function assertNotVoided(array $rows): void
    {
        self::assertSame(
            [null, null, null, self::EARLIER],
            self::voidedAt(AuthorizationRequest::class, [$rows['pending'], $rows['consumed'], $rows['finished'], $rows['voided']]),
        );
        self::assertSame(
            [null, null, self::EARLIER],
            self::voidedAt(HandoffCode::class, [$rows['unredeemed'], $rows['redeemed'], $rows['voidedCode']]),
        );
    }

    /**
     * Give the connection a request pending, consumed but unfinished, finished,
     * and voided earlier; and a code unredeemed, redeemed, and voided earlier.
     * Answers the ids by what each is.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array<string, string>
     */
    private function populate(Connection $connection): array
    {
        $now     = $this->clock->now();
        $earlier = CarbonImmutable::parse(self::EARLIER);

        return [
            'pending'    => $this->makeAuthorizationRequest($connection)->id,
            'consumed'   => $this->makeAuthorizationRequest($connection, ['consumed_at' => $now])->id,
            'finished'   => $this->makeAuthorizationRequest($connection, ['consumed_at' => $now, 'completed_at' => $now])->id,
            'voided'     => $this->makeAuthorizationRequest($connection, ['voided_at' => $earlier])->id,
            'unredeemed' => $this->makeHandoffCode($connection)->id,
            'redeemed'   => $this->makeHandoffCode($connection, ['redeemed_at' => $now])->id,
            'voidedCode' => $this->makeHandoffCode($connection, ['voided_at' => $earlier])->id,
        ];
    }

    /**
     * A complete OIDC connection of the tenant, created through the helpers so
     * its settings are stored as an update compares them.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function oidc(): Connection
    {
        return $this->created('oidc', self::OIDC);
    }

    /**
     * A complete SAML connection of the tenant, created through the helpers.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(): Connection
    {
        return $this->created('saml2', self::SAML);
    }

    /**
     * Create a connection of the protocol with the settings through the
     * helpers, and forget the freshness it asked.
     *
     * @param  string  $protocol
     * @param  array<string, string>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function created(string $protocol, array $settings): Connection
    {
        $result = $this->connections()->create(self::TENANT, $protocol, 'Example', $settings);

        $this->freshness->reset();

        return Connection::query()->whereKey((string) $result->connection?->id)->sole();
    }

    /**
     * The management helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function connections(): ConnectionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionService::class);
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
     * The id of the key the result carries, which it must.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyResult  $result
     * @return string
     */
    private static function keyOf(KeyResult $result): string
    {
        self::assertNotNull($result->key, sprintf('The helper answered %s (%s).', $result->status->value, $result->reason->value ?? 'no reason'));

        return $result->key->id;
    }

    /**
     * When each row of the model with the ids was voided, in the order given,
     * `null` for one never voided.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Models\AuthorizationRequest>|class-string<\SineMacula\Laravel\Sso\Models\HandoffCode>  $model
     * @param  list<string>  $ids
     * @return list<?string>
     */
    private static function voidedAt(string $model, array $ids): array
    {
        return array_map(static fn (string $id): ?string => $model::query()->findOrFail($id)->voided_at?->toIso8601String(), $ids);
    }

    /**
     * When each request was voided, by id, `null` for one never voided.
     *
     * @return array<string, ?string>
     */
    private static function requestsVoided(): array
    {
        $voided = [];

        foreach (AuthorizationRequest::query()->orderBy('id')->get()->all() as $request) {
            $voided[$request->id] = $request->voided_at?->toIso8601String();
        }

        return $voided;
    }

    /**
     * When each handoff code was voided, by id, `null` for one never voided.
     *
     * @return array<string, ?string>
     */
    private static function codesVoided(): array
    {
        $voided = [];

        foreach (HandoffCode::query()->orderBy('id')->get()->all() as $code) {
            $voided[$code->id] = $code->voided_at?->toIso8601String();
        }

        return $voided;
    }
}
