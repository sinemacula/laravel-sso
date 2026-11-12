<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Events;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Log\Logger;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Monolog\Handler\TestHandler;
use Monolog\Logger as Monolog;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * Runs the examples of `docs/guides/events.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContext::class)]
final class EventsExampleTest extends ExampleTestCase
{
    /** @var string The administrator's key. */
    private const string ADMINISTRATOR = 'user-7';

    /** @var list<string> Every key of a context record. */
    private const array KEYS = [
        'acting_identity_id', 'acting_identity_morph_class', 'application', 'connection_id', 'connection_tenant_id', 'identity_id',
        'identity_morph_class', 'ip', 'method', 'occurred_at', 'principal_id', 'principal_morph_class', 'protocol', 'purpose',
        'request_reference', 'session_id', 'tenant_id', 'user_agent',
    ];

    /** @var \Tests\Integration\Examples\Events\User The administrator making each change. */
    private User $administrator;

    /**
     * Make the administrator and create the application's audit table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->administrator = new User(['id' => self::ADMINISTRATOR]);

        Schema::create(AuditEntry::TABLE, static function (Blueprint $table): void {
            $table->id();
            $table->string('event');
            $table->string('tenant_id')->nullable();
            $table->string('connection_id')->nullable();
            $table->string('actor_type')->nullable();
            $table->string('actor_id')->nullable();
            $table->json('details');
            $table->json('context');
            $table->timestamps();
        });
    }

    /**
     * Drop the application's audit table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists(AuditEntry::TABLE);

        parent::tearDown();
    }

    /**
     * One listener on the contract logs every event with its context record.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOneListenerOnTheContractLogsEveryEvent(): void
    {
        config()->set('logging.channels.audit', ['driver' => 'monolog', 'handler' => TestHandler::class]);

        require __DIR__ . '/listeners/every-event.php';

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);

        // Fetches the keys, so only the audience refuses the next flow
        $this->linkThroughFlow($provider, $connectionId, new IdentityReference(User::class, 'person-1'));

        $start     = $this->startFlow(Purpose::LINK, $connectionId, new IdentityReference(User::class, 'person-1'));
        $redirect  = $this->respondAtProvider($provider, $connectionId, $start, static fn (FakeIdToken $token): FakeIdToken => $token->with('aud', 'another-client'));
        $reference = (string) $start->reference?->value;
        $logged    = self::logged();
        $flow      = array_values(array_filter($logged, static fn (array $entry): bool => $entry['context']['request_reference'] === $reference));

        self::assertSame(FailureReason::AUDIENCE_MISMATCH->value, $redirect->error);
        self::assertSame([
            'ConnectionCreated', 'ConnectionEnabled', 'AuthorizationRequestStarted', 'JwksRefreshed', 'ResultVerified', 'HandoffIssued', 'LinkCreated',
            'HandoffRedeemed', 'AuthorizationRequestStarted', 'FlowFailed',
        ], array_column($logged, 'event'));
        self::assertSame(['AuthorizationRequestStarted', 'FlowFailed'], array_column($flow, 'event'));

        foreach ($logged as $entry) {
            self::assertEqualsCanonicalizing(self::KEYS, array_keys($entry['context']));
            self::assertSame([], array_filter($entry['context'], static fn (mixed $value): bool => $value !== null && !is_string($value)));
        }

        $failed = $flow[1]['context'];

        self::assertSame($connectionId, $failed['connection_id']);
        self::assertSame(self::TENANT, $failed['connection_tenant_id']);
        self::assertNull($failed['tenant_id']);
        self::assertSame('oidc', $failed['protocol']);
        self::assertSame(self::APPLICATION, $failed['application']);
        self::assertSame(Purpose::LINK->value, $failed['purpose']);
        self::assertSame(User::class, $failed['identity_morph_class']);
        self::assertSame('person-1', $failed['identity_id']);
        self::assertNull($failed['acting_identity_id']);
    }

    /**
     * The caller given to `update()` is the event's acting identity, without
     * its session.
     *
     * @return void
     */
    public function testTheActingIdentityIsWhoTheEventSaysMadeTheChange(): void
    {
        $reported     = $this->reported();
        $connections  = app(ConnectionService::class);
        $tenantId     = self::TENANT;
        $connectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));
        $user         = $this->administrator;
        $url          = 'https://op.example.test/oauth2/v2/token';
        $request      = self::requestOnSession('/admin/sso/connections');

        $client = Clients::browser();
        // @snippet-start acting-identity
        $caller = new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId());

        $updated = $connections->update($tenantId, $connectionId, ['settings' => ['token_endpoint' => $url]], $client, $caller);
        // @snippet-end acting-identity
        self::assertTrue($updated->isSucceeded());
        self::assertSame(['token_endpoint'], $updated->changedSettings);
        self::assertCount(1, $reported);

        $event = $reported[0] ?? self::fail('The update reported nothing.');

        self::assertSame(['token_endpoint'], $event->changedSettings);
        self::assertSame(User::class, $event->context()->actingIdentityMorphClass);
        self::assertSame(self::ADMINISTRATOR, $event->context()->actingIdentityId);
        self::assertNull($event->context()->sessionId);
        self::assertSame($connectionId, $event->context()->connectionId);
        self::assertSame(self::TENANT, $event->context()->connectionTenantId);
    }

    /**
     * A change to another tenant's connection reports nothing.
     *
     * @return void
     */
    public function testARefusedChangeReportsNothing(): void
    {
        $reported     = $this->reported();
        $connectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));
        $caller       = new Caller(new IdentityReference($this->administrator->getMorphClass(), (string) $this->administrator->getKey()));

        $refused = app(ConnectionService::class)->update(
            'tenant-2',
            $connectionId,
            ['settings' => ['token_endpoint' => 'https://op.example.test/other']],
            Clients::browser(),
            $caller,
        );

        self::assertTrue($refused->isRefused());
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $refused->reason);
        self::assertCount(0, $reported);
    }

    /**
     * The audit trail keeps one entry per administration change, and none for a
     * refusal.
     *
     * @return void
     */
    public function testTheAuditTrailKeepsEveryAdministrationChange(): void
    {
        require __DIR__ . '/listeners/audit-trail.php';

        $idp          = new FakeSamlIdentityProvider;
        $caller       = new Caller(new IdentityReference($this->administrator->getMorphClass(), (string) $this->administrator->getKey()));
        $connections  = app(ConnectionService::class);
        $keys         = app(KeyService::class);
        $connectionId = (string) $connections->create(self::TENANT, 'saml2', 'Example SAML', Clients::browser(), [
            'idp_entity_id' => $idp->entityId,
            'sso_url'       => FakeSamlIdentityProvider::SSO_URL,
        ], caller: $caller)->connection?->id;

        $certificate = (string) $keys->trustCertificate(self::TENANT, $connectionId, $idp->certificate(), Clients::browser(), $caller)->key?->id;

        self::assertTrue($connections->update(self::TENANT, $connectionId, ['display_name' => 'Renamed SAML'], Clients::browser(), $caller)->isSucceeded());
        self::assertTrue($connections->update('tenant-2', $connectionId, ['display_name' => 'Not ours'], Clients::browser(), $caller)->isRefused());
        self::assertTrue($connections->enable(self::TENANT, $connectionId, Clients::browser(), $caller)->isSucceeded());

        $first  = (string) $keys->addNext(self::TENANT, $connectionId, KeyUse::SP_SIGNING, Clients::browser(), caller: $caller)->key?->id;
        $second = (string) $keys->addNext(self::TENANT, $connectionId, KeyUse::SP_SIGNING, Clients::browser(), caller: $caller)->key?->id;

        self::assertTrue($keys->makeCurrent(self::TENANT, $connectionId, $second, Clients::browser(), $caller)->isSucceeded());
        self::assertTrue($keys->retire(self::TENANT, $connectionId, $first, Clients::browser(), $caller)->isSucceeded());
        self::assertTrue(app(ConnectionLifecycle::class)->disable(self::TENANT, $connectionId, Clients::browser(), $caller)->isSucceeded());
        self::assertTrue(app(ConnectionLifecycle::class)->delete(self::TENANT, $connectionId, Clients::browser(), $caller)->isSucceeded());

        $entries = AuditEntry::query()->orderBy('id')->get()->all();

        self::assertSame([
            'ConnectionCreated', 'KeyAdded', 'ConnectionUpdated', 'ConnectionEnabled', 'KeyAdded', 'KeyMadeCurrent', 'KeyAdded', 'KeyMadeCurrent',
            'KeyRetired', 'ConnectionDisabled', 'ConnectionDeleted',
        ], array_map(static fn (AuditEntry $entry): string => $entry->event, $entries));

        foreach ($entries as $entry) {
            self::assertSame([self::TENANT, $connectionId, User::class, self::ADMINISTRATOR], [$entry->tenant_id, $entry->connection_id, $entry->actor_type, $entry->actor_id]);
            self::assertSame(self::TENANT, $entry->context['connection_tenant_id']);
            self::assertSame($connectionId, $entry->context['connection_id']);
            self::assertSame(self::ADMINISTRATOR, $entry->context['acting_identity_id']);
        }

        $fingerprint = self::details($entries[4], 'key_id', 'use', 'fingerprint')[2];

        self::assertIsString($fingerprint);

        self::assertSame([], $entries[0]->details);
        self::assertSame([$certificate, KeyUse::IDP_SIGNING->value], array_slice(self::details($entries[1], 'key_id', 'use', 'fingerprint'), 0, 2));
        self::assertSame([['display_name']], self::details($entries[2], 'changed'));
        self::assertSame([$first, KeyUse::SP_SIGNING->value, $fingerprint], self::details($entries[4], 'key_id', 'use', 'fingerprint'));
        self::assertSame([$first, null], self::details($entries[5], 'key_id', 'replaced'));
        self::assertSame([$second, KeyUse::SP_SIGNING->value], array_slice(self::details($entries[6], 'key_id', 'use', 'fingerprint'), 0, 2));
        self::assertSame([$second, $first], self::details($entries[7], 'key_id', 'replaced'));
        self::assertSame([$first, $fingerprint], self::details($entries[8], 'key_id', 'fingerprint'));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $fingerprint);
        self::assertSame([], $entries[10]->details);
    }

    /**
     * Collect the connection updates reported from now on.
     *
     * @return \ArrayObject<int, \SineMacula\Laravel\Sso\Events\ConnectionUpdated>
     */
    private function reported(): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\ConnectionUpdated> $reported */
        $reported = new \ArrayObject;

        Event::listen(ConnectionUpdated::class, static function (ConnectionUpdated $event) use ($reported): void {
            $reported->append($event);
        });

        return $reported;
    }

    /**
     * The entry's detail values by key, once its details hold exactly those
     * keys.
     *
     * @param  \Tests\Integration\Examples\Events\AuditEntry  $entry
     * @param  string  ...$keys
     * @return list<mixed>
     */
    private static function details(AuditEntry $entry, string ...$keys): array
    {
        self::assertEqualsCanonicalizing($keys, array_keys($entry->details));

        return array_values(array_map(static fn (string $key): mixed => $entry->details[$key], $keys));
    }

    /**
     * What the `audit` channel was written: each event's name and context
     * record.
     *
     * @return list<array{event: string, context: array<string, mixed>}>
     */
    private static function logged(): array
    {
        $channel = Log::channel('audit');

        self::assertInstanceOf(Logger::class, $channel);

        $monolog = $channel->getLogger();

        self::assertInstanceOf(Monolog::class, $monolog);

        $handler = $monolog->getHandlers()[0] ?? null;

        self::assertInstanceOf(TestHandler::class, $handler);

        return array_values(array_map(static fn (LogRecord $record): array => ['event' => $record->message, 'context' => $record->context], $handler->getRecords()));
    }
}
