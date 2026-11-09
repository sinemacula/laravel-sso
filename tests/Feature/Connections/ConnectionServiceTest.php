<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Secrets\MaskedSecret;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Protocols\ExampleDriver;
use Tests\TestCase;

/**
 * Feature tests for the management helpers (SSO-1.2, SSO-2.3 to SSO-2.5,
 * SSO-2.10 to SSO-2.12): every outcome of create, update, get, list and enable;
 * tenant scoping; presets; secrets kept, set and cleared; exactly the freshness
 * operations each change asks, with their configured maximum ages; a stale
 * caller refused with nothing written or reported; the event each change
 * reports; and a change to what subjects mean refused while the connection has
 * links (SSO-2.13), after freshness is asked, with what is in flight voided by
 * every trust change it allows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
#[CoversClass(ConnectionResult::class)]
#[CoversClass(ConnectionSummary::class)]
final class ConnectionServiceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The tenant the connections belong to. */
    private const string TENANT = 'tenant-1';

    /** @var string Another tenant. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var string A client secret no output may show. */
    private const string SECRET = 'the-client-secret-value';

    /** @var int The maximum age configured for trust changes, other than the default. */
    private const int TRUST_MAX_AGE = 120;

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
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
     * on, configure a maximum age for trust changes, create the tables, and
     * record events.
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
        config()->set('sso.freshness.max_age_seconds.connection_trust', self::TRUST_MAX_AGE);
        config()->set('sso.mapping.custom_attributes', ['department']);

        $this->usePackageTables();
        $this->startRecordingEvents();
    }

    /**
     * A connection is created disabled, its settings stored with their defaults
     * and no secret, its secret encrypted and masked, its mapping over the
     * protocol's defaults; trust freshness is asked with its configured age,
     * and the creation reported with the acting identity.
     *
     * @return void
     */
    public function testCreatesADisabledConnection(): void
    {
        $result = $this->service()->create(
            self::TENANT,
            'oidc',
            '  Acme  ',
            Clients::browser(),
            self::OIDC + ['client_secret' => self::SECRET],
            ['department' => 'dept'],
            caller: new Caller(new IdentityReference('user', '42')),
        );

        self::assertSame(ConnectionStatus::CREATED, $result->status);
        self::assertTrue($result->isSucceeded());
        self::assertTrue($result->isChanged());

        $summary = $result->connection;

        self::assertInstanceOf(ConnectionSummary::class, $summary);
        self::assertSame(self::TENANT, $summary->tenantId);
        self::assertSame('oidc', $summary->protocol);
        self::assertSame('Acme', $summary->displayName);
        self::assertFalse($summary->enabled);
        self::assertFalse($summary->usable);
        self::assertFalse($summary->hasCompletedSignIn);
        self::assertEquals(['client_secret' => MaskedSecret::set()], $summary->secrets);
        self::assertSame([
            'issuer'                 => 'https://idp.example.com',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint'         => 'https://idp.example.com/token',
            'jwks_uri'               => 'https://idp.example.com/jwks',
            'returns_iss'            => false,
            'client_id'              => 'client-123',
            'client_authentication'  => 'client_secret_basic',
            'scopes'                 => ['openid', 'email', 'profile'],
            'id_token_algorithms'    => ['RS256'],
            'trusted_audiences'      => [],
            'fetch_userinfo'         => false,
            'metadata_refresh'       => true,
        ], $summary->settings);
        self::assertSame(
            ['email' => 'email', 'given_name' => 'given_name', 'family_name' => 'family_name', 'display_name' => 'name', 'groups' => 'groups', 'department' => 'dept'],
            $summary->attributeMapping,
        );
        self::assertSame('2026-11-01T09:30:00+00:00', $summary->createdAt->toIso8601String());

        $stored = $this->stored($summary->id);

        self::assertSame(self::sortedByKey($summary->settings), self::sortedByKey($stored->settings));
        self::assertFalse($stored->enabled);
        self::assertTrue($this->secrets()->reveal($stored, 'client_secret')?->equals(self::SECRET));

        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, self::TRUST_MAX_AGE]], $this->freshness->asked());
        self::assertEventSequence([ConnectionCreated::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(ConnectionCreated::class, $event);
        self::assertSame($summary->id, $event->context->connectionId);
        self::assertSame(self::TENANT, $event->context->connectionTenantId);
        self::assertSame('oidc', $event->context->protocol);
        self::assertSame('user', $event->context->actingIdentityMorphClass);
        self::assertSame('42', $event->context->actingIdentityId);
    }

    /**
     * A connection may be created empty, its settings complete or not, and a
     * setting or target given as `null` is not set.
     *
     * @return void
     */
    public function testCreatesAnIncompleteConnection(): void
    {
        $result = $this->service()->create(self::TENANT, 'saml2', 'Acme', Clients::browser(), ['sso_url' => null, 'client_secret' => null], ['groups' => null]);

        $connection = $result->connection;

        self::assertSame(ConnectionStatus::CREATED, $result->status);
        self::assertNotNull($connection);
        self::assertArrayNotHasKey('sso_url', $connection->settings);
        self::assertSame('http_redirect', $connection->settings['sso_binding']);
        self::assertArrayNotHasKey('groups', $connection->attributeMapping);
        self::assertSame([], $connection->secrets);
        self::assertNull($this->stored($connection->id)->secrets);
    }

    /**
     * A preset fills in the settings and the mapping, and what is given
     * replaces what it fills in, setting by setting.
     *
     * @return void
     */
    public function testFillsInAPresetAndLetsWhatIsGivenReplaceIt(): void
    {
        $result = $this->service()->create(
            self::TENANT,
            'oidc',
            'Google',
            Clients::browser(),
            ['client_id' => 'client-123', 'scopes' => ['openid', 'email']],
            ['email' => 'mail'],
            'google',
        );

        self::assertSame(ConnectionStatus::CREATED, $result->status);

        $settings = $result->connection->settings ?? [];

        self::assertSame('https://accounts.google.com', $settings['issuer']);
        self::assertSame('https://oauth2.googleapis.com/token', $settings['token_endpoint']);
        self::assertSame(['openid', 'email'], $settings['scopes']);
        self::assertSame('client-123', $settings['client_id']);
        self::assertSame(
            ['email' => 'mail', 'given_name' => 'given_name', 'family_name' => 'family_name', 'display_name' => 'name', 'groups' => 'groups'],
            $result->connection?->attributeMapping,
        );

        $saml = $this->service()->create(self::TENANT, 'saml2', 'Entra', Clients::browser(), self::SAML, preset: 'microsoft_entra_saml');

        self::assertSame('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', $saml->connection?->attributeMapping['email']);
        self::assertSame('urn:oid:2.5.4.42', $this->service()->create(self::TENANT, 'saml2', 'Plain', Clients::browser(), self::SAML)->connection?->attributeMapping['given_name']);
    }

    /**
     * An unknown preset, or one of another protocol, is refused as a value,
     * with nothing asked, written or reported.
     *
     * @return void
     */
    public function testRefusesAnUnknownPresetOrOneOfAnotherProtocol(): void
    {
        $unknown = $this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), preset: 'nobody');
        $other   = $this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), preset: 'microsoft_entra_saml');

        self::assertSame([['preset', 'unknown']], self::violationsOf($unknown));
        self::assertSame([['preset', 'not_allowed']], self::violationsOf($other));
        self::assertSame(FailureReason::SETTINGS_INVALID, $other->reason);
        $this->assertNothingHappened();
    }

    /**
     * Every violation is collected, in order: the display name, the settings,
     * the secrets, then the mapping; nothing is asked, written or reported.
     *
     * @return void
     */
    public function testCollectsEveryViolationInOrder(): void
    {
        $settings = ['issuer' => 'http://idp.example.com', 'client_secret' => "leaked-secret-value\x01", 'color' => 'red'];
        $result   = $this->service()->create(self::TENANT, 'oidc', ' ', Clients::browser(), $settings, ['subject' => 'sub']);

        self::assertTrue($result->isInvalid());
        self::assertSame([
            ['display_name', 'required'],
            ['issuer', 'not_https'],
            ['color', 'unknown'],
            ['client_secret', 'invalid_format'],
            ['attribute_mapping.subject', 'reserved'],
        ], self::violationsOf($result));
        self::assertStringNotContainsString('leaked-secret-value', (string) json_encode($result));
        self::assertStringNotContainsString('leaked-secret-value', print_r($result, true));
        $this->assertNothingHappened();
    }

    /**
     * The display name is trimmed, then 1 to 255 characters with no control
     * character.
     *
     * @return void
     */
    public function testValidatesTheDisplayName(): void
    {
        foreach (['' => 'required', "Acme\x07" => 'invalid_format', str_repeat('n', 256) => 'too_long', "Acme\u{85}" => 'invalid_format'] as $name => $code) {
            self::assertSame([['display_name', $code]], self::violationsOf($this->service()->create(self::TENANT, 'oidc', $name, Clients::browser())), $name);
        }

        self::assertTrue($this->service()->create(self::TENANT, 'oidc', str_repeat('é', 255), Clients::browser())->isSucceeded());
        $this->assertEventSequence([ConnectionCreated::class]);
    }

    /**
     * A secret is a string of 1 to 1024 bytes with no control character, and no
     * client secret is given to a client that authenticates with
     * `private_key_jwt`.
     *
     * @return void
     */
    public function testValidatesTheSecrets(): void
    {
        $cases = [
            ['client_secret' => 5],
            ['client_secret' => ''],
            ['client_secret' => str_repeat('s', 1025)],
            ['client_secret' => "line\nbreak"],
            ['client_secret' => self::SECRET, 'client_authentication' => 'private_key_jwt'],
        ];

        $codes = [];

        foreach ($cases as $settings) {
            $codes[] = self::violationsOf($this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), $settings));
        }

        self::assertSame([
            [['client_secret', 'invalid_type']],
            [['client_secret', 'required']],
            [['client_secret', 'too_long']],
            [['client_secret', 'invalid_format']],
            [['client_secret', 'unsupported']],
        ], $codes);

        self::assertTrue($this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), ['client_secret' => str_repeat('s', 1024)])->isSucceeded());
        self::assertTrue($this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), ['client_authentication' => 'private_key_jwt'])->isSucceeded());
    }

    /**
     * Creation asks trust freshness and, for each setting given, the operation
     * it needs, each once, in the order the operations are listed.
     *
     * @return void
     */
    public function testAsksTheFreshnessOfEverySettingGiven(): void
    {
        config()->set('sso.features.idp_initiated', true);

        $result = $this->service()->create(
            self::TENANT,
            'saml2',
            'Acme',
            Clients::browser(),
            self::SAML + ['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/start', 'force_authn' => true],
        );

        self::assertTrue($result->isSucceeded());
        self::assertSame([
            [FreshnessOperation::CONNECTION_TRUST, self::TRUST_MAX_AGE],
            [FreshnessOperation::CONNECTION_IDP_INITIATED, 300],
        ], $this->freshness->asked());
    }

    /**
     * A stale caller is refused with `freshness_required`; nothing is written
     * or reported.
     *
     * @return void
     */
    public function testRefusesAStaleCreation(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), self::OIDC + ['client_secret' => self::SECRET]);

        self::assertTrue($result->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertNull($result->connection);
        self::assertSame(0, Connection::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A protocol not registered, or whose feature is off, is unavailable.
     *
     * @return void
     */
    public function testRefusesAnUnavailableProtocol(): void
    {
        config()->set('sso.features.saml2', false);

        foreach (['saml2', 'cas', '', 'OIDC'] as $protocol) {
            $result = $this->service()->create(self::TENANT, $protocol, 'Acme', Clients::browser());

            self::assertTrue($result->isRefused(), $protocol);
            self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $result->reason);
        }

        $this->assertNothingHappened();
    }

    /**
     * A protocol an application registers is created through its own settings,
     * its secrets taken out of them by name.
     *
     * @return void
     */
    public function testCreatesAConnectionOverAnApplicationsProtocol(): void
    {
        $this->protocols()->extend('example', fn (): ExampleDriver => new ExampleDriver);

        $result = $this->service()->create(
            self::TENANT,
            'example',
            'Acme',
            Clients::browser(),
            ['issuer' => 'https://idp.example.com', 'api_secret' => self::SECRET, 'region' => 'eu'],
        );

        self::assertTrue($result->isSucceeded());
        self::assertSame(['issuer' => 'https://idp.example.com', 'region' => 'eu'], $result->connection?->settings);
        self::assertEquals(['api_secret' => MaskedSecret::set()], $result->connection->secrets);
        self::assertSame([], $result->connection->attributeMapping);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, self::TRUST_MAX_AGE]], $this->freshness->asked());

        self::assertSame([['issuer', 'required']], self::violationsOf($this->service()->create(self::TENANT, 'example', 'Acme', Clients::browser())));
    }

    /**
     * An empty or overlong tenant id is the application's mistake, for every
     * helper.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesATenantIdTheTableCannotHold(): void
    {
        $calls = [
            fn (string $tenant): mixed => $this->service()->create($tenant, 'oidc', 'Acme', Clients::browser()),
            fn (string $tenant): mixed => $this->service()->update($tenant, 'x', [], Clients::browser()),
            fn (string $tenant): mixed => $this->service()->get($tenant, 'x'),
            fn (string $tenant): mixed => $this->service()->list($tenant),
            fn (string $tenant): mixed => $this->service()->enable($tenant, 'x', Clients::browser()),
        ];

        foreach ($calls as $call) {
            foreach (['', str_repeat('t', 256)] as $tenant) {

                try {
                    $call($tenant);
                    self::fail('The tenant id was accepted.');
                } catch (\InvalidArgumentException $exception) {
                    self::assertSame('A tenant id is 1 to 255 bytes.', $exception->getMessage());
                }
            }
        }

        $this->assertNothingHappened();
    }

    /**
     * A tenant id of exactly 255 bytes, the longest the table holds, is
     * accepted and stored as given by every helper.
     *
     * @return void
     */
    public function testAcceptsTheLongestTenantId(): void
    {
        $tenant = str_repeat('t', ConnectionFinder::MAX_TENANT_ID_LENGTH);

        $created = $this->service()->create($tenant, 'oidc', 'Acme', Clients::browser(), self::OIDC);
        $id      = (string) $created->connection?->id;

        self::assertSame(ConnectionStatus::CREATED, $created->status);
        self::assertSame($tenant, $this->stored($id)->tenant_id);
        self::assertSame($id, $this->service()->get($tenant, $id)?->id);
        self::assertSame([$id], array_map(static fn (ConnectionSummary $summary): string => $summary->id, $this->service()->list($tenant)));
        self::assertSame(ConnectionStatus::UPDATED, $this->service()->update($tenant, $id, ['display_name' => 'Renamed'], Clients::browser())->status);
        self::assertSame(ConnectionStatus::ENABLED, $this->service()->enable($tenant, $id, Clients::browser())->status);
        self::assertNull($this->service()->get(self::TENANT, $id));
    }

    /**
     * An update changes what is given, asks trust freshness for a trust
     * setting, saves through the model and reports the names that changed.
     *
     * @return void
     */
    public function testUpdatesASetting(): void
    {
        $id = $this->createOidc();

        $this->clock->advance(60);

        $result = $this->service()->update(
            self::TENANT,
            $id,
            ['settings' => ['issuer' => 'https://login.example.com']],
            Clients::browser(),
            new Caller(new IdentityReference('user', '7')),
        );

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame(['issuer'], $result->changedSettings);
        self::assertSame('https://login.example.com', $result->connection?->settings['issuer']);
        self::assertSame('2026-11-01T09:31:00+00:00', $result->connection->updatedAt->toIso8601String());
        self::assertSame('https://login.example.com', $this->stored($id)->settings['issuer']);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, self::TRUST_MAX_AGE]], $this->freshness->asked());
        self::assertEventSequence([ConnectionUpdated::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(ConnectionUpdated::class, $event);
        self::assertSame(['issuer'], $event->changedSettings);
        self::assertSame('7', $event->context->actingIdentityId);
    }

    /**
     * A secret not named in an update is kept as stored (SSO-2.5), and a change
     * that needs no freshness asks none.
     *
     * @return void
     */
    public function testKeepsTheStoredSecretWhenAnUpdateDoesNotNameIt(): void
    {
        $id     = $this->createOidc();
        $before = $this->stored($id)->secrets;

        $result = $this->service()->update(self::TENANT, $id, ['display_name' => 'Acme SSO', 'settings' => ['scopes' => ['openid', 'email']]], Clients::browser());

        self::assertSame(['scopes', 'display_name'], $result->changedSettings);
        self::assertEquals(['client_secret' => MaskedSecret::set()], $result->connection?->secrets);
        self::assertSame($before, $this->stored($id)->secrets);
        self::assertSame('Acme SSO', $this->stored($id)->display_name);
        self::assertSame([], $this->freshness->asked());
        self::assertEventSequence([ConnectionUpdated::class]);
    }

    /**
     * A secret given sets it, and counts as changed even when it is the same.
     *
     * @return void
     */
    public function testSetsASecret(): void
    {
        $id = $this->createOidc();

        $result = $this->service()->update(self::TENANT, $id, ['settings' => ['client_secret' => 'a-new-client-secret']], Clients::browser());

        self::assertSame(['client_secret'], $result->changedSettings);
        self::assertTrue($this->secrets()->reveal($this->stored($id), 'client_secret')?->equals('a-new-client-secret'));
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, self::TRUST_MAX_AGE]], $this->freshness->asked());

        $same = $this->service()->update(self::TENANT, $id, ['settings' => ['client_secret' => 'a-new-client-secret']], Clients::browser());

        self::assertSame(ConnectionStatus::UPDATED, $same->status);
        self::assertSame(['client_secret'], $same->changedSettings);
        self::assertEventSequence([ConnectionUpdated::class, ConnectionUpdated::class]);
    }

    /**
     * A secret given as `null` clears it; clearing one not set changes nothing.
     *
     * @return void
     */
    public function testClearsASecret(): void
    {
        $id = $this->createOidc();

        $result = $this->service()->update(self::TENANT, $id, ['settings' => ['client_secret' => null]], Clients::browser());

        self::assertSame(['client_secret'], $result->changedSettings);
        self::assertEquals(['client_secret' => MaskedSecret::unset()], $result->connection?->secrets);
        self::assertNull($this->stored($id)->secrets);

        $again = $this->service()->update(self::TENANT, $id, ['settings' => ['client_secret' => null]], Clients::browser());

        self::assertSame(ConnectionStatus::UNCHANGED, $again->status);
        self::assertEventSequence([ConnectionUpdated::class]);
    }

    /**
     * A setting given as `null` is removed, and a default comes back as its
     * default.
     *
     * @return void
     */
    public function testRemovesASetting(): void
    {
        $id = $this->createOidc(['userinfo_endpoint' => 'https://idp.example.com/userinfo', 'client_authentication' => 'client_secret_post']);

        $result = $this->service()->update(self::TENANT, $id, ['settings' => ['userinfo_endpoint' => null, 'client_authentication' => null]], Clients::browser());

        self::assertSame(['userinfo_endpoint', 'client_authentication'], $result->changedSettings);
        self::assertArrayNotHasKey('userinfo_endpoint', $this->stored($id)->settings);
        self::assertSame('client_secret_basic', $this->stored($id)->settings['client_authentication']);

        $default = $this->service()->update(self::TENANT, $id, ['settings' => ['client_authentication' => null, 'returns_iss' => false]], Clients::browser());

        self::assertSame(ConnectionStatus::UNCHANGED, $default->status);
    }

    /**
     * The mapping's targets are replaced or removed, as one change that needs
     * no freshness.
     *
     * @return void
     */
    public function testUpdatesTheMapping(): void
    {
        $id = $this->createOidc();

        $result = $this->service()->update(self::TENANT, $id, ['attribute_mapping' => ['department' => 'dept', 'groups' => null, 'email' => 'mail']], Clients::browser());

        self::assertSame(['attribute_mapping'], $result->changedSettings);
        self::assertSame(
            self::sortedByKey(['email' => 'mail', 'given_name' => 'given_name', 'family_name' => 'family_name', 'display_name' => 'name', 'department' => 'dept']),
            self::sortedByKey($this->stored($id)->attribute_mapping),
        );
        self::assertSame([], $this->freshness->asked());

        self::assertSame(
            [['attribute_mapping.tenant_id', 'reserved']],
            self::violationsOf($this->service()->update(self::TENANT, $id, ['attribute_mapping' => ['tenant_id' => 'tid']], Clients::browser())),
        );
    }

    /**
     * A custom target the application does not declare in
     * `sso.mapping.custom_attributes` is refused as `not_allowed` at its
     * target, on creation and on update, and nothing is stored; once declared,
     * the same mapping is saved.
     *
     * @return void
     */
    public function testRefusesACustomTargetTheApplicationDoesNotDeclare(): void
    {
        $id      = $this->createOidc();
        $mapping = ['attribute_mapping' => ['badge_number' => 'badge']];

        self::assertSame([['attribute_mapping.badge_number', 'not_allowed']], self::violationsOf($this->service()->update(self::TENANT, $id, $mapping, Clients::browser())));
        self::assertArrayNotHasKey('badge_number', $this->stored($id)->attribute_mapping);

        $created = $this->service()->create(self::TENANT, 'oidc', 'Badges', Clients::browser(), [], ['badge_number' => 'badge']);

        self::assertSame([['attribute_mapping.badge_number', 'not_allowed']], self::violationsOf($created));

        config()->set('sso.mapping.custom_attributes', ['department', 'badge_number']);

        self::assertSame(['attribute_mapping'], $this->service()->update(self::TENANT, $id, $mapping, Clients::browser())->changedSettings);
        self::assertSame('badge', $this->stored($id)->attribute_mapping['badge_number'] ?? null);
    }

    /**
     * Changed names come in order: settings as the protocol names them, then
     * secrets, the display name and the mapping.
     *
     * @return void
     */
    public function testNamesWhatChangedInOrder(): void
    {
        $id = $this->createOidc();

        $result = $this->service()->update(self::TENANT, $id, [
            'attribute_mapping' => ['department' => 'dept'],
            'display_name'      => 'Renamed',
            'settings'          => ['scopes' => ['openid'], 'client_secret' => 'rotated-secret', 'issuer' => 'https://login.example.com'],
        ], Clients::browser());

        self::assertSame(['issuer', 'scopes', 'client_secret', 'display_name', 'attribute_mapping'], $result->changedSettings);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, self::TRUST_MAX_AGE]], $this->freshness->asked());
    }

    /**
     * Each change asks only the operations its changed settings need, each
     * once, in the order the operations are listed; turning IdP-initiated
     * sign-in off asks as turning it on does.
     *
     * @return void
     */
    public function testAsksTheFreshnessOfWhatChanged(): void
    {
        config()->set('sso.features.idp_initiated', true);

        $id = (string) $this->service()->create(self::TENANT, 'saml2', 'Acme', Clients::browser(), self::SAML)->connection?->id;

        $this->freshness->reset();

        $this->service()->update(self::TENANT, $id, ['settings' => ['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/start']], Clients::browser());

        self::assertSame([FreshnessOperation::CONNECTION_IDP_INITIATED], $this->freshness->operations());

        $this->freshness->reset();

        $this->service()->update(
            self::TENANT,
            $id,
            ['settings' => ['idp_initiated_start_url' => 'https://app.example.com/begin', 'sso_url' => 'https://idp.example.com/login', 'force_authn' => true]],
            Clients::browser(),
        );

        self::assertSame([FreshnessOperation::CONNECTION_TRUST, FreshnessOperation::CONNECTION_IDP_INITIATED], $this->freshness->operations());

        $this->freshness->reset();

        $this->service()->update(self::TENANT, $id, ['settings' => ['force_authn' => false]], Clients::browser());

        self::assertSame([], $this->freshness->operations());

        $this->freshness->reset();

        $this->service()->update(self::TENANT, $id, ['settings' => ['requested_authn_context' => ['urn:x:y']]], Clients::browser());

        self::assertSame([FreshnessOperation::CONNECTION_TRUST], $this->freshness->operations());

        $this->freshness->reset();

        $off = $this->service()->update(self::TENANT, $id, ['settings' => ['idp_initiated' => false, 'idp_initiated_start_url' => null]], Clients::browser());

        self::assertSame(['idp_initiated', 'idp_initiated_start_url'], $off->changedSettings);
        self::assertSame([FreshnessOperation::CONNECTION_IDP_INITIATED], $this->freshness->operations());
    }

    /**
     * An update giving what is stored succeeds as `unchanged`, and asks, writes
     * and reports nothing.
     *
     * @return void
     */
    public function testAnUpdateThatChangesNothingIsUnchanged(): void
    {
        $id   = $this->createOidc();
        $rows = $this->rows();

        $this->clock->advance(60);

        $result = $this->service()->update(self::TENANT, $id, [
            'display_name'      => ' Acme ',
            'settings'          => self::OIDC + ['scopes' => ['openid', 'email', 'profile']],
            'attribute_mapping' => ['email' => 'email'],
        ], Clients::browser());

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
        self::assertTrue($result->isSucceeded());
        self::assertFalse($result->isChanged());
        self::assertSame($id, $result->connection?->id);
        self::assertSame([], $result->changedSettings);
        self::assertSame($rows, $this->rows());
        $this->assertNothingHappened();

        self::assertSame(ConnectionStatus::UNCHANGED, $this->service()->update(self::TENANT, $id, [], Clients::browser())->status);
    }

    /**
     * A map given again in another key order, as a form may send it or a native
     * JSON column hand it back, is what is stored: the update is `unchanged`,
     * and asks, writes and reports nothing. A list in another order is a
     * change.
     *
     * @return void
     */
    public function testAMapGivenInAnotherKeyOrderIsUnchanged(): void
    {
        $id   = $this->createOidc(['extra_parameters' => ['login_hint' => 'x', 'prompt' => 'login']]);
        $rows = $this->rows();

        $result = $this->service()->update(self::TENANT, $id, [
            'settings'          => ['extra_parameters' => ['prompt' => 'login', 'login_hint' => 'x']],
            'attribute_mapping' => ['groups' => 'groups', 'email' => 'email'],
        ], Clients::browser());

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
        self::assertSame([], $result->changedSettings);
        self::assertSame($rows, $this->rows());
        $this->assertNothingHappened();

        DB::table('sso_connections')->where('id', $id)->update([
            'attribute_mapping' => json_encode(self::sortedByKey($this->stored($id)->attribute_mapping), JSON_THROW_ON_ERROR),
        ]);

        $rows = $this->rows();

        self::assertSame(ConnectionStatus::UNCHANGED, $this->service()->update(self::TENANT, $id, ['attribute_mapping' => ['email' => 'email']], Clients::browser())->status);
        self::assertSame($rows, $this->rows());
        $this->assertNothingHappened();

        $reordered = $this->service()->update(self::TENANT, $id, ['settings' => ['scopes' => ['profile', 'email', 'openid']]], Clients::browser());

        self::assertSame(['scopes'], $reordered->changedSettings);
    }

    /**
     * A change to the tenant or the protocol is `immutable`, any other key
     * `unknown`, and a change of the wrong type `invalid_type`.
     *
     * @return void
     */
    public function testRefusesAnImmutableOrUnknownKey(): void
    {
        $id   = $this->createOidc();
        $rows = $this->rows();

        $result = $this->service()->update(
            self::TENANT,
            $id,
            ['tenant_id' => self::OTHER_TENANT, 'protocol' => 'saml2', 'enabled' => true, 'display_name' => 5, 'settings' => 'x', 'attribute_mapping' => null],
            Clients::browser(),
        );

        self::assertSame([
            ['tenant_id', 'immutable'],
            ['protocol', 'immutable'],
            ['enabled', 'unknown'],
            ['display_name', 'invalid_type'],
            ['settings', 'invalid_type'],
            ['attribute_mapping', 'invalid_type'],
        ], self::violationsOf($result));
        self::assertSame($rows, $this->rows());
        $this->assertNothingHappened();
    }

    /**
     * The merged connection is validated as a whole; nothing is written.
     *
     * @return void
     */
    public function testValidatesTheMergedConnection(): void
    {
        $id   = $this->createOidc();
        $rows = $this->rows();

        $result = $this->service()->update(
            self::TENANT,
            $id,
            ['display_name' => '', 'settings' => ['client_authentication' => 'private_key_jwt', 'client_secret' => 'another-secret', 'scopes' => ['email']]],
            Clients::browser(),
        );

        self::assertSame([
            ['display_name', 'required'],
            ['scopes', 'openid_scope_required'],
            ['client_secret', 'unsupported'],
        ], self::violationsOf($result));
        self::assertSame($rows, $this->rows());
        $this->assertNothingHappened();
    }

    /**
     * Another tenant's connection, an unknown one and an id that cannot be one
     * are not found, and nothing is asked.
     *
     * @return void
     */
    public function testAnUpdateFindsOnlyTheTenantsConnection(): void
    {
        $id = $this->createOidc();

        foreach ([[self::OTHER_TENANT, $id], [self::TENANT, '01jbunknownconnection00000'], [self::TENANT, '']] as [$tenant, $connection]) {
            $result = $this->service()->update($tenant, $connection, ['display_name' => 'Taken'], Clients::browser());

            self::assertTrue($result->isRefused());
            self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $result->reason);
        }

        self::assertSame('Acme', $this->stored($id)->display_name);
        $this->assertNothingHappened();
    }

    /**
     * A connection whose protocol is unavailable cannot be changed.
     *
     * @return void
     */
    public function testAnUpdateRefusesAnUnavailableProtocol(): void
    {
        $id = $this->createOidc();

        config()->set('sso.features.oidc', false);

        $result = $this->service()->update(self::TENANT, $id, ['display_name' => 'Renamed'], Clients::browser());

        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $result->reason);
        self::assertSame('Acme', $this->stored($id)->display_name);
        $this->assertNothingHappened();
    }

    /**
     * A stale caller is refused with `freshness_required`; nothing is written
     * or reported.
     *
     * @return void
     */
    public function testRefusesAStaleUpdate(): void
    {
        $id   = $this->createOidc();
        $rows = $this->rows();

        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->service()->update(self::TENANT, $id, ['settings' => ['client_id' => 'another-client', 'client_secret' => 'another-secret']], Clients::browser());

        self::assertTrue($result->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame($rows, $this->rows());
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, self::TRUST_MAX_AGE]], $this->freshness->asked());
        $this->assertNoEvents();
    }

    /**
     * A tenant's connection is read, and another tenant's, or an unknown one,
     * is `null`.
     *
     * @return void
     */
    public function testGetsOnlyTheTenantsConnection(): void
    {
        $id = $this->createOidc();

        $summary = $this->service()->get(self::TENANT, $id);

        self::assertInstanceOf(ConnectionSummary::class, $summary);
        self::assertSame($id, $summary->id);
        self::assertEquals(['client_secret' => MaskedSecret::set()], $summary->secrets);
        self::assertStringNotContainsString(self::SECRET, (string) json_encode($summary));

        self::assertNull($this->service()->get(self::OTHER_TENANT, $id));
        self::assertNull($this->service()->get(self::TENANT, '01jbunknownconnection00000'));
        $this->assertNothingHappened();
    }

    /**
     * A tenant's connections are listed oldest first, and no other tenant's.
     *
     * @return void
     */
    public function testListsTheTenantsConnectionsOldestFirst(): void
    {
        $first = $this->createOidc();

        $this->clock->advance(60);

        $this->service()->create(self::OTHER_TENANT, 'oidc', 'Theirs', Clients::browser());
        $second = (string) $this->service()->create(self::TENANT, 'saml2', 'Second', Clients::browser(), self::SAML)->connection?->id;

        self::assertSame([$first, $second], array_map(static fn (ConnectionSummary $summary): string => $summary->id, $this->service()->list(self::TENANT)));
        self::assertSame([], $this->service()->list('tenant-3'));
    }

    /**
     * Enabling asks its freshness, sets the flag, and reports it; it needs no
     * complete settings, and the connection stays unusable until it is.
     *
     * @return void
     */
    public function testEnablesAConnection(): void
    {
        $id = (string) $this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser())->connection?->id;

        $this->freshness->reset();
        $this->startRecordingEvents();

        $result = $this->service()->enable(self::TENANT, $id, Clients::browser(), new Caller(new IdentityReference('user', '42')));

        self::assertSame(ConnectionStatus::ENABLED, $result->status);
        self::assertTrue($result->isChanged());
        self::assertTrue($result->connection?->enabled);
        self::assertFalse($result->connection->usable);
        self::assertTrue($this->stored($id)->enabled);
        self::assertSame([[FreshnessOperation::CONNECTION_ENABLE, 300]], $this->freshness->asked());
        self::assertEventSequence([ConnectionEnabled::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(ConnectionEnabled::class, $event);
        self::assertSame($id, $event->context->connectionId);
        self::assertSame('42', $event->context->actingIdentityId);
    }

    /**
     * Enabling an enabled connection asks freshness, then succeeds as
     * `unchanged`, writing and reporting nothing.
     *
     * @return void
     */
    public function testEnablingAnEnabledConnectionIsUnchanged(): void
    {
        $connection = $this->makeConnection(['enabled' => true]);
        $rows       = $this->rows();

        $result = $this->service()->enable(self::TENANT, $connection->id, Clients::browser());

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
        self::assertSame($rows, $this->rows());
        self::assertSame([FreshnessOperation::CONNECTION_ENABLE], $this->freshness->operations());
        $this->assertNoEvents();

        $this->freshness->answer(FreshnessOutcome::STALE);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $this->service()->enable(self::TENANT, $connection->id, Clients::browser())->reason);
    }

    /**
     * A stale caller is refused, and the connection stays disabled.
     *
     * @return void
     */
    public function testRefusesAStaleEnable(): void
    {
        $connection = $this->makeConnection();

        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->service()->enable(self::TENANT, $connection->id, Clients::browser());

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertFalse($this->stored($connection->id)->enabled);
        $this->assertNoEvents();
    }

    /**
     * Another tenant's connection, an unknown one, and one whose protocol is
     * unavailable are refused before freshness is asked.
     *
     * @return void
     */
    public function testEnablingRefusesWhatItCannotFindOrUse(): void
    {
        $connection = $this->makeConnection();
        $retired    = $this->makeConnection(['protocol' => 'retired']);

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->service()->enable(self::OTHER_TENANT, $connection->id, Clients::browser())->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $this->service()->enable(self::TENANT, '01jbunknownconnection00000', Clients::browser())->reason);
        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $this->service()->enable(self::TENANT, $retired->id, Clients::browser())->reason);
        self::assertFalse($this->stored($connection->id)->enabled);
        $this->assertNothingHappened();
    }

    /**
     * Enabling never touches whether a sign-in has been completed.
     *
     * @return void
     */
    public function testEnablingNeverWritesTheCompletedSignIn(): void
    {
        $completed = $this->makeConnection(['has_completed_sign_in' => true]);
        $fresh     = $this->makeConnection();

        $this->service()->enable(self::TENANT, $completed->id, Clients::browser());
        $this->service()->enable(self::TENANT, $fresh->id, Clients::browser());

        self::assertTrue($this->stored($completed->id)->has_completed_sign_in);
        self::assertFalse($this->stored($fresh->id)->has_completed_sign_in);
    }

    /**
     * Creation always asks trust freshness, even when no setting given needs
     * it, and a setting given as `null` neither asks freshness nor stops the
     * settings after it.
     *
     * @return void
     */
    public function testCreationAsksTrustFreshnessAndSkipsANullSetting(): void
    {
        $result = $this->service()->create(self::TENANT, 'saml2', 'Acme', Clients::browser(), ['idp_initiated' => null, 'force_authn' => true]);

        self::assertSame(ConnectionStatus::CREATED, $result->status);
        self::assertTrue($this->stored((string) $result->connection?->id)->settings['force_authn']);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, self::TRUST_MAX_AGE]], $this->freshness->asked());
    }

    /**
     * A SAML update names the settings it removes and adds in the order the
     * protocol names them, wherever they fall in what is stored.
     *
     * @return void
     */
    public function testNamesTheSamlSettingsRemovedAndAddedInOrder(): void
    {
        $id = (string) $this->service()->create(self::TENANT, 'saml2', 'Acme', Clients::browser(), self::SAML)->connection?->id;

        $removed = $this->service()->update(self::TENANT, $id, ['settings' => ['idp_entity_id' => null, 'sso_url' => 'https://idp.example.com/login']], Clients::browser());
        $added   = $this->service()->update(self::TENANT, $id, ['settings' => ['idp_entity_id' => self::SAML['idp_entity_id']]], Clients::browser());

        self::assertSame(['idp_entity_id', 'sso_url'], $removed->changedSettings);
        self::assertSame(['idp_entity_id'], $added->changedSettings);
        self::assertSame(self::SAML['idp_entity_id'], $this->stored($id)->settings['idp_entity_id']);
    }

    /**
     * An application's protocol is updated through its own settings, which name
     * no order of their own.
     *
     * @return void
     */
    public function testUpdatesAConnectionOverAnApplicationsProtocol(): void
    {
        $this->protocols()->extend('example', fn (): ExampleDriver => new ExampleDriver);

        $id = (string) $this->service()->create(
            self::TENANT,
            'example',
            'Acme',
            Clients::browser(),
            ['issuer' => 'https://idp.example.com', 'region' => 'eu'],
        )->connection?->id;
        $result = $this->service()->update(self::TENANT, $id, ['settings' => ['region' => 'us']], Clients::browser());

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame(['region'], $result->changedSettings);
        self::assertSame('us', $this->stored($id)->settings['region']);
    }

    /**
     * An update or an enable for a tenant id the table cannot hold is refused
     * before any transaction is opened.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesABadTenantIdBeforeOpeningATransaction(): void
    {
        $opened = 0;

        Event::listen(TransactionBeginning::class, static function () use (&$opened): void {
            $opened++;
        });

        $calls = [
            fn (): mixed => $this->service()->update('', 'x', [], Clients::browser()),
            fn (): mixed => $this->service()->enable('', 'x', Clients::browser()),
        ];

        foreach ($calls as $call) {

            try {
                $call();
                self::fail('The tenant id was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A tenant id is 1 to 255 bytes.', $exception->getMessage());
            }
        }

        self::assertSame(0, $opened);
    }

    /**
     * Rows of `[protocol, changes]`: a change to each setting that may alter
     * what existing subjects mean.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>}>
     */
    public static function provideSubjectChanges(): iterable
    {
        yield from [
            'the oidc issuer'        => ['oidc', ['issuer' => 'https://login.example.com']],
            'the oidc client id'     => ['oidc', ['client_id' => 'client-456']],
            'the saml entity id'     => ['saml2', ['idp_entity_id' => 'https://idp.example.com/other']],
            'the saml subject'       => ['saml2', ['subject_source' => 'attribute', 'subject_attribute' => 'urn:oid:0.9.2342.19200300.100.1.1']],
            'the saml nameid format' => ['saml2', ['name_id_format' => 'unspecified']],
        ];
    }

    /**
     * A change to a subject setting of a connection with an active link is
     * refused with `connection_has_links` once freshness is fresh, and nothing
     * is written, voided or reported.
     *
     * @param  string  $protocol
     * @param  array<string, mixed>  $settings
     * @return void
     */
    #[DataProvider('provideSubjectChanges')]
    public function testASubjectChangeIsRefusedWhileTheConnectionHasALink(string $protocol, array $settings): void
    {
        $id         = $protocol === 'oidc' ? $this->createOidc() : $this->createSaml();
        $connection = $this->stored($id);

        $this->makeLink($connection);

        $request = $this->makeAuthorizationRequest($connection);
        $before  = $this->rows();
        $result  = $this->service()->update(self::TENANT, $id, ['settings' => $settings], Clients::browser());

        self::assertSame(ConnectionStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::CONNECTION_HAS_LINKS, $result->reason);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, self::TRUST_MAX_AGE]], $this->freshness->asked());
        self::assertSame($before, $this->rows());
        self::assertNull(AuthorizationRequest::query()->findOrFail($request->id)->voided_at);
        $this->assertNoEvents();
    }

    /**
     * A reservation that expires after now counts as a link; one that expired
     * at now, or before, does not.
     *
     * @return void
     */
    public function testOnlyAnUnexpiredReservationCountsAsALink(): void
    {
        $id         = $this->createOidc();
        $connection = $this->stored($id);
        $now        = $this->clock->now();
        $reserved   = ['state' => LinkState::RESERVED, 'reservation_reference' => str_repeat('r', 32)];

        $expired = $this->makeLink($connection, 'expired', $reserved + ['reservation_expires_at' => $now->subSecond()]);
        $expiry  = $this->makeLink($connection, 'expiring', $reserved + ['reservation_expires_at' => $now]);
        $open    = $this->makeLink($connection, 'open', $reserved + ['reservation_expires_at' => $now->addSecond()]);

        self::assertSame(
            FailureReason::CONNECTION_HAS_LINKS,
            $this->service()->update(self::TENANT, $id, ['settings' => ['issuer' => 'https://login.example.com']], Clients::browser())->reason,
        );

        $open->delete();

        $result = $this->service()->update(self::TENANT, $id, ['settings' => ['issuer' => 'https://login.example.com']], Clients::browser());

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame(['issuer'], $result->changedSettings);
        self::assertSame('https://login.example.com', $this->stored($id)->settings['issuer']);
        self::assertSame(0, $expired->newQuery()->whereKey([$expired->id, $expiry->id])->count());
    }

    /**
     * A link of another connection does not hold this connection's subjects.
     *
     * @return void
     */
    public function testAnotherConnectionsLinkDoesNotCount(): void
    {
        $id    = $this->createOidc();
        $other = $this->stored($this->createOidc());

        $this->makeLink($other);

        self::assertSame(ConnectionStatus::UPDATED, $this->service()->update(self::TENANT, $id, ['settings' => ['client_id' => 'client-456']], Clients::browser())->status);
    }

    /**
     * Freshness is asked before the links are: a stale caller is refused with
     * `freshness_required`, however many links the connection has.
     *
     * @return void
     */
    public function testAStaleSubjectChangeIsRefusedForFreshnessFirst(): void
    {
        $id = $this->createOidc();

        $this->makeLink($this->stored($id));
        $this->freshness->answer(FreshnessOutcome::STALE);

        self::assertSame(
            FailureReason::FRESHNESS_REQUIRED,
            $this->service()->update(self::TENANT, $id, ['settings' => ['issuer' => 'https://login.example.com']], Clients::browser())->reason,
        );
        $this->assertNoEvents();
    }

    /**
     * A trust change that alters no subject is allowed on a connection with
     * links, and voids what is in flight through it.
     *
     * @return void
     */
    public function testATrustChangeThatAltersNoSubjectIsAllowedWithLinksAndVoids(): void
    {
        $id         = $this->createOidc();
        $connection = $this->stored($id);

        $this->makeLink($connection);

        $request = $this->makeAuthorizationRequest($connection);
        $code    = $this->makeHandoffCode($connection);
        $result  = $this->service()->update(self::TENANT, $id, ['settings' => ['token_endpoint' => 'https://idp.example.com/oauth2/token']], Clients::browser());

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame(['token_endpoint'], $result->changedSettings);
        self::assertSame('2026-11-01T09:30:00+00:00', AuthorizationRequest::query()->findOrFail($request->id)->voided_at?->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', HandoffCode::query()->findOrFail($code->id)->voided_at?->toIso8601String());
        $this->assertEventSequence([ConnectionUpdated::class]);
    }

    /**
     * A change that alters no subject and asks no trust is allowed with links
     * and voids nothing.
     *
     * @return void
     */
    public function testAChangeThatAsksNoTrustVoidsNothing(): void
    {
        $id         = $this->createOidc();
        $connection = $this->stored($id);

        $this->makeLink($connection);

        $request = $this->makeAuthorizationRequest($connection);

        self::assertSame(
            ConnectionStatus::UPDATED,
            $this->service()->update(self::TENANT, $id, ['display_name' => 'Renamed', 'settings' => ['scopes' => ['openid']]], Clients::browser())->status,
        );
        self::assertNull(AuthorizationRequest::query()->findOrFail($request->id)->voided_at);
    }

    /**
     * A change under a lock its caller holds, as a subject migration makes it,
     * is applied through the same rules.
     *
     * @return void
     */
    public function testAChangeUnderACallersLockIsApplied(): void
    {
        $id = $this->createOidc();

        $result = DB::transaction(
            fn (): ConnectionResult => $this->service()->changeLocked(Connection::query()->lockForUpdate()->findOrFail($id), ['display_name' => 'Renamed'], Clients::browser()),
        );

        self::assertTrue($result->isChanged());
        self::assertSame('Renamed', Connection::query()->findOrFail($id)->display_name);
    }

    /**
     * The management helpers, resolved per request.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function service(): ConnectionService
    {
        $service = $this->app?->make(ConnectionService::class);

        self::assertInstanceOf(ConnectionService::class, $service);

        return $service;
    }

    /**
     * The protocol registry.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ProtocolManager
     */
    private function protocols(): ProtocolManager
    {
        $protocols = $this->app?->make(ProtocolManager::class);

        self::assertInstanceOf(ProtocolManager::class, $protocols);

        return $protocols;
    }

    /**
     * The connections' secrets.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSecrets
     */
    private function secrets(): ConnectionSecrets
    {
        $secrets = $this->app?->make(ConnectionSecrets::class);

        self::assertInstanceOf(ConnectionSecrets::class, $secrets);

        return $secrets;
    }

    /**
     * Create a complete OIDC connection named `Acme` with its client secret,
     * then forget what was asked and reported.
     *
     * @param  array<string, mixed>  $settings
     * @return string
     */
    private function createOidc(array $settings = []): string
    {
        $result = $this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), $settings + self::OIDC + ['client_secret' => self::SECRET]);

        self::assertSame(ConnectionStatus::CREATED, $result->status);

        $this->freshness->reset();
        $this->startRecordingEvents();

        return (string) $result->connection?->id;
    }

    /**
     * Create a complete SAML connection named `Acme`, then forget what was
     * asked and reported.
     *
     * @return string
     */
    private function createSaml(): string
    {
        $result = $this->service()->create(self::TENANT, 'saml2', 'Acme', Clients::browser(), self::SAML);

        self::assertSame(ConnectionStatus::CREATED, $result->status);

        $this->freshness->reset();
        $this->startRecordingEvents();

        return (string) $result->connection?->id;
    }

    /**
     * The connection as stored.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function stored(string $id): Connection
    {
        return Connection::query()->findOrFail($id);
    }

    /**
     * Every row of the connections table, as stored.
     *
     * @return list<array<string, mixed>>
     */
    private function rows(): array
    {
        return array_values(array_map(static fn (object $row): array => (array) $row, DB::table('sso_connections')->orderBy('id')->get()->all()));
    }

    /**
     * Assert no freshness was asked and no event reported.
     *
     * @return void
     */
    private function assertNothingHappened(): void
    {
        self::assertSame([], $this->freshness->asked(), 'Freshness was asked.');
        $this->assertNoEvents();
    }

    /**
     * The map, ordered by key, so maps read back from a native JSON column,
     * which orders keys its own way, compare by content alone.
     *
     * @param  array<array-key, mixed>  $map
     * @return array<array-key, mixed>
     */
    private static function sortedByKey(array $map): array
    {
        ksort($map, SORT_STRING);

        return $map;
    }

    /**
     * Each violation of the result as `[setting, code]`.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(ConnectionResult $result): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $result->violations);
    }
}
