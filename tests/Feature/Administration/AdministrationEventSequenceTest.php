<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\Fixtures\Protocols\ExampleDriver;
use Tests\TestCase;

/**
 * Feature tests of the exact sequence of administration events each management
 * helper reports (SSO-10.3, SSO-10.4): one event per change, naming the
 * connection, its tenant and protocol and the acting identity, and never a flow
 * identifier; a connection update naming exactly what changed, in the helper's
 * order, a secret by name and never by value; nothing for a change that changed
 * nothing; and nothing for any refusal.
 *
 * Keys are generated on P-256, since RSA generation is slow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdministrationEvents::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(KeyService::class)]
final class AdministrationEventSequenceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The tenant whose connections the helpers act on. */
    private const string TENANT = 'tenant-1';

    /** @var string A tenant with no connection. */
    private const string OTHER_TENANT = 'tenant-2';

    /** @var string An id no connection or key has. */
    private const string UNKNOWN = '01jbunknown000000000000000';

    /** @var string The client secret a connection is created with. */
    private const string SECRET = 'the-client-secret-value';

    /** @var string The client secret it is rotated to. */
    private const string ROTATED_SECRET = 'the-rotated-client-secret';

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

    /** @var \SineMacula\Laravel\Sso\Administration\ActingIdentity Who makes each change. */
    private ActingIdentity $actor;

    /**
     * Bind a fixed clock and a freshness contract that answers `fresh`, turn
     * both protocols on, create the tables, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->actor = new ActingIdentity('App\Models\User', '42');

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.oidc', true);
        config()->set('sso.mapping.custom_attributes', ['department']);

        $this->createConnectionTables();
        $this->createFlowTables();
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
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * Creating a connection reports `ConnectionCreated`, and nothing else.
     *
     * @return void
     */
    public function testCreatingReportsConnectionCreated(): void
    {
        $id = $this->createOidc();

        $this->assertEventSequence([ConnectionCreated::class]);
        $this->assertReportedFor($this->recordedEvents()[0], $id, 'oidc');
    }

    /**
     * An update reports one `ConnectionUpdated` naming exactly what changed, in
     * the helper's order (settings as the protocol names them, then secrets,
     * the display name and the mapping), the client secret by name and never by
     * value.
     *
     * @return void
     */
    public function testAnUpdateNamesExactlyWhatChangedInOrder(): void
    {
        $id = $this->createOidc();

        $this->startRecordingEvents();

        $result = $this->connections()->update(self::TENANT, $id, [
            'attribute_mapping' => ['department' => 'dept'],
            'display_name'      => 'Renamed',
            'settings'          => [
                'client_secret'  => self::ROTATED_SECRET,
                'scopes'         => ['openid', 'email'],
                'token_endpoint' => 'https://idp.example.com/oauth/token',
            ],
        ], $this->actor);

        $this->assertEventSequence([ConnectionUpdated::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(ConnectionUpdated::class, $event);
        self::assertSame(['token_endpoint', 'scopes', 'client_secret', 'display_name', 'attribute_mapping'], $event->changedSettings);
        self::assertSame($result->changedSettings, $event->changedSettings);
        self::assertStringNotContainsString(self::ROTATED_SECRET, serialize($event));
        self::assertStringNotContainsString('https://idp.example.com/oauth/token', serialize($event));

        $this->assertReportedFor($event, $id, 'oidc');
    }

    /**
     * An update of one setting names that setting alone, and one of the secret
     * alone names the secret.
     *
     * @return void
     */
    public function testAnUpdateOfOneSettingNamesItAlone(): void
    {
        $id = $this->createOidc();

        $this->startRecordingEvents();

        $this->connections()->update(self::TENANT, $id, ['settings' => ['token_endpoint' => 'https://idp.example.com/oauth/token']], $this->actor);
        $this->connections()->update(self::TENANT, $id, ['settings' => ['client_secret' => self::ROTATED_SECRET]], $this->actor);

        $this->assertEventSequence([ConnectionUpdated::class, ConnectionUpdated::class]);

        [$setting, $secret] = $this->recordedEvents();

        self::assertInstanceOf(ConnectionUpdated::class, $setting);
        self::assertInstanceOf(ConnectionUpdated::class, $secret);
        self::assertSame(['token_endpoint'], $setting->changedSettings);
        self::assertSame(['client_secret'], $secret->changedSettings);
    }

    /**
     * An update that gives what is stored changes nothing, and reports nothing.
     *
     * @return void
     */
    public function testAnUpdateChangingNothingReportsNothing(): void
    {
        $id = $this->createOidc();

        $this->startRecordingEvents();

        $result = $this->connections()->update(self::TENANT, $id, [
            'display_name' => 'Acme',
            'settings'     => ['token_endpoint' => self::OIDC['token_endpoint'], 'scopes' => ['openid', 'email', 'profile']],
        ], $this->actor);

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
        $this->assertNoEvents();
    }

    /**
     * Enabling a connection reports `ConnectionEnabled`; enabling it again
     * changes nothing and reports nothing.
     *
     * @return void
     */
    public function testEnablingReportsOnceAndNeverAgain(): void
    {
        $id = $this->createOidc();

        $this->startRecordingEvents();

        self::assertSame(ConnectionStatus::ENABLED, $this->connections()->enable(self::TENANT, $id, $this->actor)->status);

        $this->assertEventSequence([ConnectionEnabled::class]);
        $this->assertReportedFor($this->recordedEvents()[0], $id, 'oidc');

        $this->startRecordingEvents();

        self::assertSame(ConnectionStatus::UNCHANGED, $this->connections()->enable(self::TENANT, $id, $this->actor)->status);

        $this->assertNoEvents();
    }

    /**
     * The first key of a use is reported added as current, then made current
     * with nothing replaced; the second is reported added as next, alone.
     *
     * @return void
     */
    public function testAddingKeysReportsAddedThenMadeCurrent(): void
    {
        $id = $this->createSaml();

        $this->startRecordingEvents();

        $first = $this->addNext($id);

        $this->assertEventSequence([KeyAdded::class, KeyMadeCurrent::class]);

        [$added, $madeCurrent] = $this->recordedEvents();

        self::assertInstanceOf(KeyAdded::class, $added);
        self::assertSame([$first->id, KeyUse::SP_SIGNING, KeyState::CURRENT, $first->key->fingerprint], [$added->keyId, $added->use, $added->state, $added->fingerprint]);
        self::assertEquals($first->notAfter, $added->notAfter);
        self::assertInstanceOf(KeyMadeCurrent::class, $madeCurrent);
        self::assertSame(
            [$first->id, KeyUse::SP_SIGNING, $first->key->fingerprint, null],
            [$madeCurrent->keyId, $madeCurrent->use, $madeCurrent->fingerprint, $madeCurrent->previousKeyId],
        );

        $this->startRecordingEvents();

        $second = $this->addNext($id);

        $this->assertEventSequence([KeyAdded::class]);

        $next = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyAdded::class, $next);
        self::assertSame([$second->id, KeyState::NEXT], [$next->keyId, $next->state]);

        foreach ([$added, $madeCurrent, $next] as $event) {
            $this->assertReportedFor($event, $id, 'saml2');
        }
    }

    /**
     * Making the next key current reports `KeyMadeCurrent` naming the key it
     * replaced; retiring that key reports `KeyRetired`.
     *
     * @return void
     */
    public function testMakingCurrentAndRetiringReportEachChange(): void
    {
        $id      = $this->createSaml();
        $current = $this->addNext($id);
        $next    = $this->addNext($id);

        $this->startRecordingEvents();

        self::assertTrue($this->keys()->makeCurrent(self::TENANT, $id, $next->id, $this->actor)->isSucceeded());

        $this->assertEventSequence([KeyMadeCurrent::class]);

        $madeCurrent = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyMadeCurrent::class, $madeCurrent);
        self::assertSame([$next->id, $next->key->fingerprint, $current->id], [$madeCurrent->keyId, $madeCurrent->fingerprint, $madeCurrent->previousKeyId]);
        $this->assertReportedFor($madeCurrent, $id, 'saml2');

        $this->startRecordingEvents();

        self::assertTrue($this->keys()->retire(self::TENANT, $id, $current->id, $this->actor)->isSucceeded());

        $this->assertEventSequence([KeyRetired::class]);

        $retired = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyRetired::class, $retired);
        self::assertSame([$current->id, KeyUse::SP_SIGNING, $current->key->fingerprint], [$retired->keyId, $retired->use, $retired->fingerprint]);
        $this->assertReportedFor($retired, $id, 'saml2');
    }

    /**
     * Trusting a certificate reports `KeyAdded` with the trusted certificate's
     * use and no state; distrusting it reports `KeyRetired`.
     *
     * @return void
     */
    public function testTrustingAndDistrustingACertificateReportEachChange(): void
    {
        $id = $this->createSaml();

        $this->startRecordingEvents();

        $trusted = $this->keys()->trustCertificate(self::TENANT, $id, Certificates::distinct(30), $this->actor)->key;

        self::assertInstanceOf(KeySummary::class, $trusted);

        $this->assertEventSequence([KeyAdded::class]);

        $added = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyAdded::class, $added);
        self::assertSame([$trusted->id, KeyUse::IDP_SIGNING, null, $trusted->key->fingerprint], [$added->keyId, $added->use, $added->state, $added->fingerprint]);
        self::assertNotNull($added->notAfter);
        self::assertEquals($trusted->notAfter, $added->notAfter);
        $this->assertReportedFor($added, $id, 'saml2');

        $this->startRecordingEvents();

        self::assertTrue($this->keys()->distrustCertificate(self::TENANT, $id, $trusted->id, $this->actor)->isSucceeded());

        $this->assertEventSequence([KeyRetired::class]);

        $retired = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyRetired::class, $retired);
        self::assertSame([$trusted->id, KeyUse::IDP_SIGNING, $trusted->key->fingerprint], [$retired->keyId, $retired->use, $retired->fingerprint]);
        $this->assertReportedFor($retired, $id, 'saml2');
    }

    /**
     * A connection over a protocol the application registered is reported by
     * that protocol's name, and its own secret by name alone.
     *
     * @return void
     */
    public function testARegisteredProtocolIsReportedByItsName(): void
    {
        $this->protocols()->extend('example', fn (): ExampleDriver => new ExampleDriver);

        $created = $this->connections()->create(
            self::TENANT,
            'example',
            'Example',
            ['issuer' => 'https://idp.example.com', 'api_secret' => 'example-api-secret'],
            actor: $this->actor,
        );
        $id = (string) $created->connection?->id;

        $this->connections()->update(self::TENANT, $id, ['settings' => ['api_secret' => 'rotated-api-secret']], $this->actor);

        $this->assertEventSequence([ConnectionCreated::class, ConnectionUpdated::class]);

        [$create, $update] = $this->recordedEvents();

        self::assertInstanceOf(ConnectionUpdated::class, $update);
        self::assertSame(['api_secret'], $update->changedSettings);
        self::assertStringNotContainsString('rotated-api-secret', serialize($update));

        $this->assertReportedFor($create, $id, 'example');
        $this->assertReportedFor($update, $id, 'example');
    }

    /**
     * Every refusal a helper answers with.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'stale creation' => ['stale create', FailureReason::FRESHNESS_REQUIRED];
        yield 'stale update' => ['stale update', FailureReason::FRESHNESS_REQUIRED];
        yield 'stale enable' => ['stale enable', FailureReason::FRESHNESS_REQUIRED];
        yield 'stale key addition' => ['stale add next', FailureReason::FRESHNESS_REQUIRED];
        yield 'stale make current' => ['stale make current', FailureReason::FRESHNESS_REQUIRED];
        yield 'stale retirement' => ['stale retire', FailureReason::FRESHNESS_REQUIRED];
        yield 'stale trust' => ['stale trust', FailureReason::FRESHNESS_REQUIRED];
        yield 'stale distrust' => ['stale distrust', FailureReason::FRESHNESS_REQUIRED];
        yield 'unknown connection' => ['unknown connection', FailureReason::CONNECTION_NOT_FOUND];
        yield 'connection of another tenant' => ['another tenant', FailureReason::CONNECTION_NOT_FOUND];
        yield 'key of an unknown connection' => ['key of an unknown connection', FailureReason::CONNECTION_NOT_FOUND];
        yield 'unknown key' => ['unknown key', FailureReason::KEY_NOT_FOUND];
        yield 'own key distrusted' => ['own key distrusted', FailureReason::KEY_NOT_FOUND];
        yield 'invalid creation' => ['invalid creation', FailureReason::SETTINGS_INVALID];
        yield 'invalid update' => ['invalid update', FailureReason::SETTINGS_INVALID];
        yield 'certificate trusted twice' => ['certificate trusted twice', FailureReason::SETTINGS_INVALID];
        yield 'second next key' => ['second next key', FailureReason::KEY_STATE_CONFLICT];
        yield 'current key retired' => ['current key retired', FailureReason::KEY_STATE_CONFLICT];
        yield 'unregistered protocol' => ['unregistered protocol', FailureReason::PROTOCOL_UNAVAILABLE];
        yield 'protocol switched off' => ['protocol switched off', FailureReason::PROTOCOL_UNAVAILABLE];
    }

    /**
     * Every refusal reports nothing: no administration event, and no failure
     * event either.
     *
     * @param  string  $refusal
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusalReportsNothing(string $refusal, FailureReason $reason): void
    {
        $oidc    = $this->createOidc();
        $saml    = $this->createSaml();
        $current = $this->addNext($saml);
        $next    = $this->addNext($saml);
        $trusted = $this->keys()->trustCertificate(self::TENANT, $saml, Certificates::distinct(31), $this->actor)->key;

        self::assertInstanceOf(KeySummary::class, $trusted);

        $this->startRecordingEvents();

        if (str_starts_with($refusal, 'stale ')) {
            $this->app?->instance(Freshness::class, FakeFreshness::stale());
        }

        $result = $this->refuse($refusal, $oidc, $saml, $current->id, $next->id, $trusted->id);

        self::assertFalse($result->isSucceeded());
        self::assertSame($reason, $result->reason);
        $this->assertNoEvents();
    }

    /**
     * Run the refusal against the connections and keys prepared.
     *
     * @param  string  $refusal
     * @param  string  $oidc
     * @param  string  $saml
     * @param  string  $current
     * @param  string  $next
     * @param  string  $trusted
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult|\SineMacula\Laravel\Sso\Keys\KeyResult
     *
     * @throws \LogicException
     */
    private function refuse(string $refusal, string $oidc, string $saml, string $current, string $next, string $trusted): ConnectionResult|KeyResult
    {
        if ($refusal === 'protocol switched off') {
            config()->set('sso.features.oidc', false);
        }

        $refusals = [...$this->connectionRefusals($oidc), ...$this->keyRefusals($oidc, $saml, $current, $next, $trusted)];

        if (!array_key_exists($refusal, $refusals)) {
            throw new \LogicException(sprintf('No refusal [%s].', $refusal));
        }

        return $refusals[$refusal]();
    }

    /**
     * Each refused change to a connection, by name, to run against the OIDC
     * connection prepared.
     *
     * @param  string  $oidc
     * @return array<string, \Closure(): \SineMacula\Laravel\Sso\Connections\ConnectionResult>
     */
    private function connectionRefusals(string $oidc): array
    {
        return [
            'stale create' => fn (): ConnectionResult => $this->connections()->create(self::TENANT, 'oidc', 'Second', self::OIDC, actor: $this->actor),
            'stale update' => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $oidc,
                ['settings' => ['token_endpoint' => 'https://idp.example.com/oauth/token']],
                $this->actor,
            ),
            'stale enable'       => fn (): ConnectionResult => $this->connections()->enable(self::TENANT, $oidc, $this->actor),
            'unknown connection' => fn (): ConnectionResult => $this->connections()->update(self::TENANT, self::UNKNOWN, ['display_name' => 'Renamed'], $this->actor),
            'another tenant'     => fn (): ConnectionResult => $this->connections()->enable(self::OTHER_TENANT, $oidc, $this->actor),
            'invalid creation'   => fn (): ConnectionResult => $this->connections()->create(self::TENANT, 'oidc', '   ', self::OIDC, actor: $this->actor),
            'invalid update'     => fn (): ConnectionResult => $this->connections()->update(
                self::TENANT,
                $oidc,
                ['settings' => ['token_endpoint' => 'not a url']],
                $this->actor,
            ),
            'unregistered protocol' => fn (): ConnectionResult => $this->connections()->create(self::TENANT, 'unregistered', 'Acme', actor: $this->actor),
            'protocol switched off' => fn (): ConnectionResult => $this->connections()->update(self::TENANT, $oidc, ['display_name' => 'Renamed'], $this->actor),
        ];
    }

    /**
     * Each refused change to a key or certificate, by name, to run against the
     * connections and keys prepared.
     *
     * @param  string  $oidc
     * @param  string  $saml
     * @param  string  $current
     * @param  string  $next
     * @param  string  $trusted
     * @return array<string, \Closure(): \SineMacula\Laravel\Sso\Keys\KeyResult>
     */
    private function keyRefusals(string $oidc, string $saml, string $current, string $next, string $trusted): array
    {
        return [
            'stale add next'               => fn (): KeyResult => $this->keys()->addNext(self::TENANT, $oidc, KeyUse::CLIENT_ASSERTION, KeyType::EC, $this->actor),
            'stale make current'           => fn (): KeyResult => $this->keys()->makeCurrent(self::TENANT, $saml, $next, $this->actor),
            'stale retire'                 => fn (): KeyResult => $this->keys()->retire(self::TENANT, $saml, $next, $this->actor),
            'stale trust'                  => fn (): KeyResult => $this->keys()->trustCertificate(self::TENANT, $saml, Certificates::distinct(32), $this->actor),
            'stale distrust'               => fn (): KeyResult => $this->keys()->distrustCertificate(self::TENANT, $saml, $trusted, $this->actor),
            'key of an unknown connection' => fn (): KeyResult => $this->keys()->makeCurrent(self::TENANT, self::UNKNOWN, $next, $this->actor),
            'unknown key'                  => fn (): KeyResult => $this->keys()->retire(self::TENANT, $saml, self::UNKNOWN, $this->actor),
            'own key distrusted'           => fn (): KeyResult => $this->keys()->distrustCertificate(self::TENANT, $saml, $current, $this->actor),
            'certificate trusted twice'    => fn (): KeyResult => $this->keys()->trustCertificate(self::TENANT, $saml, Certificates::distinct(31), $this->actor),
            'second next key'              => fn (): KeyResult => $this->keys()->addNext(self::TENANT, $saml, KeyUse::SP_SIGNING, KeyType::RSA, $this->actor),
            'current key retired'          => fn (): KeyResult => $this->keys()->retire(self::TENANT, $saml, $current, $this->actor),
        ];
    }

    /**
     * Assert the event's context names the connection, the tenant, the protocol
     * and the acting identity, the time from the clock, and no flow identifier
     * or identity.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  string  $connectionId
     * @param  string  $protocol
     * @return void
     */
    private function assertReportedFor(SsoEvent $event, string $connectionId, string $protocol): void
    {
        $context = $event->context();

        self::assertSame($connectionId, $context->connectionId);
        self::assertSame(self::TENANT, $context->connectionTenantId);
        self::assertSame($protocol, $context->protocol);
        self::assertSame('App\Models\User', $context->actingIdentityMorphClass);
        self::assertSame('42', $context->actingIdentityId);
        self::assertNull($context->requestReference);
        self::assertNull($context->identityMorphClass);
        self::assertNull($context->identityId);
        self::assertNull($context->application);
        self::assertNull($context->purpose);
        self::assertSame('2026-11-01T09:30:00.000000Z', $context->toArray()['occurred_at']);
    }

    /**
     * Create a complete OIDC connection named `Acme`, with its client secret.
     *
     * @return string
     */
    private function createOidc(): string
    {
        $result = $this->connections()->create(self::TENANT, 'oidc', 'Acme', self::OIDC + ['client_secret' => self::SECRET], actor: $this->actor);

        self::assertSame(ConnectionStatus::CREATED, $result->status);

        return (string) $result->connection?->id;
    }

    /**
     * Create a complete SAML connection named `Acme`.
     *
     * @return string
     */
    private function createSaml(): string
    {
        $result = $this->connections()->create(self::TENANT, 'saml2', 'Acme', self::SAML, actor: $this->actor);

        self::assertSame(ConnectionStatus::CREATED, $result->status);

        return (string) $result->connection?->id;
    }

    /**
     * Add a P-256 signing key to the SAML connection.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private function addNext(string $connectionId): KeySummary
    {
        $key = $this->keys()->addNext(self::TENANT, $connectionId, KeyUse::SP_SIGNING, KeyType::RSA, $this->actor)->key;

        self::assertInstanceOf(KeySummary::class, $key);

        return $key;
    }

    /**
     * The connection helpers, as the container builds them.
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
     * The protocol registry.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ProtocolManager
     */
    private function protocols(): ProtocolManager
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ProtocolManager::class);
    }
}
