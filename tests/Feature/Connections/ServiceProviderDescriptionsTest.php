<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Protocols\ExampleDriver;
use Tests\TestCase;

/**
 * Feature tests for the service provider description helper (SSO-5.9): a SAML
 * connection described as its metadata, by its driver; a disabled or incomplete
 * connection described too; an unknown connection and another tenant's refused
 * with the same answer, and the tenant matched exactly; a protocol that is not
 * available refused; any protocol's driver asked through the registry; no fresh
 * authentication asked; and nothing written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ServiceProviderDescriptions::class)]
final class ServiceProviderDescriptionsTest extends TestCase
{
    use UsesConnections;

    /** @var string The tenant whose connections are described. */
    private const string TENANT = 'tenant-1';

    /** @var array<string, string> Complete identity provider settings. */
    private const array SETTINGS = ['idp_entity_id' => 'https://idp.example.com/entity', 'sso_url' => 'https://idp.example.com/sso'];

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract, which the helper must never ask. */
    private RecordingFreshness $freshness;

    /**
     * Bind a fixed clock and a recording freshness contract, configure the
     * endpoints, switch SAML on, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');

        $this->usePackageTables();
    }

    /**
     * A SAML connection is described as the metadata its driver writes, valid
     * against the SAML 2.0 metadata schema, without asking for fresh
     * authentication or writing anything.
     *
     * @return void
     */
    public function testDescribesASamlConnectionAsItsMetadata(): void
    {
        $connection = $this->saml(true, self::SETTINGS);
        $writes     = $this->countWrites();

        $description = $this->descriptions()->describe(self::TENANT, $connection->id);

        self::assertTrue($description->isAvailable());
        self::assertNull($description->reason);
        self::assertSame('application/samlmetadata+xml', $description->contentType);
        self::assertEquals(app(ProtocolManager::class)->protocol(Saml2Driver::NAME)->describe($connection), $description);
        self::assertStringStartsWith(
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://api.example.com/auth/sso/connections/' . $connection->id . '/metadata">',
            (string) $description->body,
        );
        self::assertSame('EntityDescriptor', (new HardenedParser)->parse((string) $description->body, MessageKind::METADATA, 1048576)->documentElement?->localName);
        self::assertSame([], $this->freshness->asked());
        self::assertSame(0, $writes->count);
    }

    /**
     * A disabled connection, and one with no identity provider settings, is
     * described as an enabled, complete one is, so it can be registered before
     * it is enabled.
     *
     * @return void
     */
    public function testDescribesADisabledOrIncompleteConnection(): void
    {
        $disabled   = $this->saml(false, self::SETTINGS);
        $incomplete = $this->saml(false, []);
        $enabled    = $this->saml(true, self::SETTINGS);

        foreach ([$disabled, $incomplete] as $connection) {

            $description = $this->descriptions()->describe(self::TENANT, $connection->id);

            self::assertTrue($description->isAvailable());
            self::assertSame('application/samlmetadata+xml', $description->contentType);
            self::assertSame(
                str_replace($enabled->id, $connection->id, (string) $this->descriptions()->describe(self::TENANT, $enabled->id)->body),
                $description->body,
            );
        }
    }

    /**
     * Rows of `[tenant, connection id]`: a connection the tenant does not have,
     * as named by the case.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideConnectionsTheTenantDoesNotHave(): iterable
    {
        yield from [
            'an unknown connection'           => [self::TENANT, '01jbunknownconnection00000'],
            'another tenant\'s connection'    => [self::TENANT, 'other'],
            'a tenant differing only in case' => ['Tenant-1', 'own'],
            'a tenant with a trailing space'  => ['tenant-1 ', 'own'],
            'an empty connection id'          => [self::TENANT, ''],
            'an overlong connection id'       => [self::TENANT, str_repeat('a', 27)],
        ];
    }

    /**
     * A connection the tenant does not have is `connection_unavailable`, the
     * same answer whether it is unknown or another tenant's, with no driver
     * asked and no fresh authentication asked.
     *
     * @param  string  $tenant
     * @param  string  $connectionId
     * @return void
     */
    #[DataProvider('provideConnectionsTheTenantDoesNotHave')]
    public function testRefusesAConnectionTheTenantDoesNotHave(string $tenant, string $connectionId): void
    {
        $own   = $this->saml(true, self::SETTINGS);
        $other = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2', 'enabled' => true, 'settings' => self::SETTINGS]);
        $id    = match ($connectionId) {
            'own'   => $own->id,
            'other' => $other->id,
            default => $connectionId,
        };

        $description = $this->descriptions()->describe($tenant, $id);
        $unknown     = $this->descriptions()->describe(self::TENANT, '01jbunknownconnection00000');

        self::assertFalse($description->isAvailable());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $description->reason);
        self::assertNull($description->contentType);
        self::assertNull($description->body);
        self::assertEquals($unknown, $description);
        self::assertEquals(ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE), $description);
        self::assertSame([], $this->freshness->asked());
    }

    /**
     * Another tenant's connection is described for that tenant, so the refusal
     * above is the tenant's, not the connection's.
     *
     * @return void
     */
    public function testDescribesAConnectionForItsOwnTenant(): void
    {
        $other = $this->makeConnection(['tenant_id' => 'tenant-2', 'protocol' => 'saml2', 'enabled' => true, 'settings' => self::SETTINGS]);

        self::assertFalse($this->descriptions()->describe(self::TENANT, $other->id)->isAvailable());
        self::assertTrue($this->descriptions()->describe('tenant-2', $other->id)->isAvailable());
    }

    /**
     * A tenant id the connections table cannot hold is the application's
     * mistake, an `InvalidArgumentException`.
     *
     * @return void
     */
    public function testRefusesATenantIdTheTableCannotHold(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A tenant id is 1 to 255 bytes.');

        $this->descriptions()->describe('', '01jbunknownconnection00000');
    }

    /**
     * A connection whose protocol has its feature off, or no driver registered
     * under it, is `protocol_unavailable`, with no driver asked.
     *
     * @return void
     */
    public function testRefusesAConnectionWhoseProtocolIsNotAvailable(): void
    {
        $saml         = $this->saml(true, self::SETTINGS);
        $unregistered = $this->makeConnection(['protocol' => 'cas', 'enabled' => true, 'settings' => []]);

        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $this->descriptions()->describe(self::TENANT, $unregistered->id)->reason);

        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', true);

        $refused = $this->descriptions()->describe(self::TENANT, $saml->id);

        self::assertEquals(ServiceProviderDescription::unavailable(FailureReason::PROTOCOL_UNAVAILABLE), $refused);

        config()->set('sso.features.saml2', true);

        self::assertTrue($this->descriptions()->describe(self::TENANT, $saml->id)->isAvailable());
    }

    /**
     * A connection over a protocol an application registered is described by
     * that protocol's driver, through the registry, unchanged.
     *
     * @return void
     */
    public function testAsksTheDriverOfTheConnectionsProtocol(): void
    {
        app(ProtocolManager::class)->extend('example', fn (): ExampleDriver => new ExampleDriver);

        $connection  = $this->makeConnection(['protocol' => 'example', 'enabled' => false, 'settings' => []]);
        $description = $this->descriptions()->describe(self::TENANT, $connection->id);

        self::assertEquals(ServiceProviderDescription::document('application/json', '{"connection":"' . $connection->id . '"}'), $description);
    }

    /**
     * The helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions
     */
    private function descriptions(): ServiceProviderDescriptions
    {
        return app(ServiceProviderDescriptions::class);
    }

    /**
     * A SAML connection of the tenant, enabled or not, with the settings given.
     *
     * @param  bool  $enabled
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(bool $enabled, array $settings): Connection
    {
        return $this->makeConnection(['protocol' => 'saml2', 'enabled' => $enabled, 'settings' => $settings]);
    }

    /**
     * Count every statement that writes, from now on.
     *
     * @return object{count: int}
     */
    private function countWrites(): object
    {
        $writes = new class {
            /** @var int The statements that wrote. */
            public int $count = 0;
        };

        DB::listen(static function (QueryExecuted $query) use ($writes): void {

            if (preg_match('/^\s*(?:insert|update|delete|replace)\b/i', $query->sql) !== 1) {
                return;
            }

            $writes->count++;
        });

        return $writes;
    }
}
