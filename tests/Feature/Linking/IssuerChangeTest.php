<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ImportSaver;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyReset;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Metadata\ValidatedFetch;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Tests that changing a connection's issuer resets its linking policy and
 * raises `linking_version`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkingPolicyReset::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(SubjectMigration::class)]
final class IssuerChangeTest extends LinkingTestCase
{
    /** @var string The issuer the change moves the connection to. */
    private const string NEW_ISSUER = 'https://multi-organization.example.net';

    /** @var string When the acknowledgement was given. */
    private const string ACKNOWLEDGED_AT = '2026-11-01T00:00:00Z';

    /** @var array<string, bool|int|string|null> What is left of a policy reset. */
    private const array RESET = [
        'enabled'               => false,
        'issuer_class'          => null,
        'organization_claim'    => null,
        'organization_value'    => null,
        'saml_attribute'        => null,
        'saml_attribute_format' => null,
        'acknowledged'          => false,
        'version'               => 1,
    ];

    /**
     * Bind a fresh caller.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
    }

    /**
     * An eligible flow reserves: what every test below takes away by changing
     * the issuer.
     *
     * @return void
     */
    public function testWithTheIssuerUnchangedItReserves(): void
    {
        $this->start();

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(1, Link::query()->count());
    }

    /**
     * Rows of `[the policy as it was, the names reported]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function providePolicies(): iterable
    {
        yield 'a single organisation' => [
            ['linking_issuer_class' => 'single_organization'],
            ['issuer', 'linking.enabled', 'linking.issuer_class', 'linking.acknowledged'],
        ];
        yield 'a shared issuer' => [
            ['linking_issuer_class' => 'shared', 'linking_organization_claim' => 'org', 'linking_organization_value' => 'acme', 'linking_acknowledged_at' => null],
            ['issuer', 'linking.enabled', 'linking.issuer_class', 'linking.organization_claim', 'linking.organization_value'],
        ];
    }

    /**
     * An issuer update resets exactly the policy, and `enabled` alone cannot
     * turn it back on.
     *
     * @param  array<string, mixed>  $policy
     * @param  list<string>  $names
     * @return void
     */
    #[DataProvider('providePolicies')]
    public function testAnIssuerUpdateResetsThePolicy(array $policy, array $names): void
    {
        $this->connection->forceFill($policy)->save();

        $result = $this->update(['settings' => ['issuer' => self::NEW_ISSUER]]);

        self::assertTrue($result->isChanged());
        self::assertSame($names, $result->changedSettings);
        self::assertSame(self::RESET, $this->reread()->getLinkingSettings());
        self::assertSame(0, Link::query()->count());

        $updates = array_values(array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof ConnectionUpdated));

        self::assertCount(1, $updates);
        self::assertInstanceOf(ConnectionUpdated::class, $updates[0]);
        self::assertSame($names, $updates[0]->changedSettings);

        $this->start();

        self::assertSame(FailureReason::UNLINKED, $this->complete()->reason);
        self::assertSame(0, Link::query()->count());
        self::assertSame(
            ['issuer_class' => 'required'],
            self::codes(app(LinkingPolicyService::class)->change('tenant-1', $this->connection->id, ['enabled' => true], Clients::browser())),
        );
    }

    /**
     * What was never stated is not reported, and raises nothing: an issuer
     * change of a connection with no policy is that change alone.
     *
     * @return void
     */
    public function testAConnectionWithNoPolicyResetsNothing(): void
    {
        $this->connection->forceFill(['linking_enabled' => false, 'linking_issuer_class' => null, 'linking_acknowledged_at' => null])->save();

        $result = $this->update(['settings' => ['issuer' => self::NEW_ISSUER]]);

        self::assertSame(['issuer'], $result->changedSettings);
        self::assertSame(0, $this->reread()->linking_version);
    }

    /**
     * Linking already off with a classification left over reports only what the
     * reset changes.
     *
     * @return void
     */
    public function testOnlyWhatChangesIsReported(): void
    {
        $this->connection->forceFill(['linking_enabled' => false, 'linking_acknowledged_at' => null])->save();

        $result = $this->update(['settings' => ['issuer' => self::NEW_ISSUER]]);

        self::assertSame(['issuer', 'linking.issuer_class'], $result->changedSettings);
        self::assertSame(self::RESET, $this->reread()->getLinkingSettings());
    }

    /**
     * Any other change, of trust or not, leaves the policy and its version as
     * they are.
     *
     * @return void
     */
    public function testAnotherChangeLeavesThePolicy(): void
    {
        $before = $this->reread()->getLinkingSettings();

        $result = $this->update(['display_name' => 'Renamed']);

        self::assertSame(['display_name'], $result->changedSettings);
        self::assertSame($before, $this->reread()->getLinkingSettings());

        $this->connection = $this->openIdConnection();

        $result = $this->update(['settings' => ['token_endpoint' => 'https://idp.example.com/token-2']]);

        self::assertSame(['token_endpoint'], $result->changedSettings);
        self::assertTrue($this->reread()->linking_enabled);
        self::assertSame('single_organization', $this->reread()->linking_issuer_class);
        self::assertSame(0, $this->reread()->linking_version);
    }

    /**
     * An OpenID Connect `issuer` is one such setting, and its `client_id`,
     * which also alters what subjects mean, is not.
     *
     * @return void
     */
    public function testOnOpenIdConnectTheIssuerIsTheSetting(): void
    {
        $this->connection = $this->openIdConnection();

        $client = $this->update(['settings' => ['client_id' => 'client-2']]);

        self::assertSame(['client_id'], $client->changedSettings);
        self::assertTrue($this->reread()->linking_enabled);

        $issuer = $this->update(['settings' => ['issuer' => self::NEW_ISSUER]]);

        self::assertContains('linking.enabled', $issuer->changedSettings);
        self::assertFalse($this->reread()->linking_enabled);
        self::assertSame(1, $this->reread()->linking_version);
    }

    /**
     * On SAML the entity id is the issuer setting: changing it clears the
     * acknowledgement and keeps the attribute name.
     *
     * @return void
     */
    public function testOnSamlTheEntityIdIsTheSetting(): void
    {
        $this->connection = $this->samlConnection();

        $result = $this->update(['settings' => ['idp_entity_id' => self::NEW_ISSUER]]);

        self::assertSame(['idp_entity_id', 'linking.enabled', 'linking.issuer_class', 'linking.acknowledged'], $result->changedSettings);
        self::assertSame([
            'enabled'               => false,
            'issuer_class'          => null,
            'organization_claim'    => null,
            'organization_value'    => null,
            'saml_attribute'        => 'email',
            'saml_attribute_format' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
            'acknowledged'          => false,
            'version'               => 1,
        ], $this->reread()->getLinkingSettings());
    }

    /**
     * A migration that moves the connection to another issuer resets the policy
     * in its transaction, whatever it does with the links.
     *
     * @return void
     */
    public function testAMigrationResetsThePolicy(): void
    {
        $link = $this->makeLink($this->connection, 'old-subject', ['issuer' => VerifyingDriver::ISSUER]);

        $result = app(SubjectMigration::class)->migrate(
            'tenant-1',
            $this->connection->id,
            ['settings' => ['issuer' => self::NEW_ISSUER]],
            [$link->id => ['new-subject']],
            [],
            Clients::browser(),
        );

        self::assertTrue($result->isChanged());
        self::assertSame(['issuer', 'linking.enabled', 'linking.issuer_class', 'linking.acknowledged'], $result->changedSettings);
        self::assertSame(self::RESET, $this->reread()->getLinkingSettings());
    }

    /**
     * A migration refused by a relink rolls the reset back with everything
     * else.
     *
     * @return void
     */
    public function testARefusedMigrationResetsNothing(): void
    {
        $link = $this->makeLink($this->connection, 'old-subject', ['issuer' => VerifyingDriver::ISSUER]);

        $before = $this->reread()->getLinkingSettings();
        $result = app(SubjectMigration::class)->migrate(
            'tenant-1',
            $this->connection->id,
            ['settings' => ['issuer' => self::NEW_ISSUER]],
            [$link->id => [123]],
            [],
            Clients::browser(),
        );

        self::assertFalse($result->isChanged());
        self::assertSame($before, $this->reread()->getLinkingSettings());
    }

    /**
     * An import that names another issuer resets the policy too.
     *
     * @return void
     */
    public function testAnImportResetsThePolicy(): void
    {
        $this->connection = $this->openIdConnection();

        $fetch  = new ValidatedFetch($this->clock->now());
        $result = app(ImportSaver::class)->save('tenant-1', $this->connection->id, ['settings' => ['issuer' => self::NEW_ISSUER]], $fetch, Clients::browser());

        self::assertTrue($result->isChanged());
        self::assertContains('linking.enabled', $result->changedSettings);
        self::assertFalse($this->reread()->linking_enabled);
        self::assertNull($this->reread()->linking_issuer_class);
        self::assertNull($this->reread()->linking_acknowledged_at);
        self::assertSame(1, $this->reread()->linking_version);
    }

    /**
     * Update the connection under test.
     *
     * @param  array<string, mixed>  $changes
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function update(array $changes): ConnectionResult
    {
        return app(ConnectionService::class)->update('tenant-1', $this->connection->id, $changes, Clients::browser());
    }

    /**
     * The connection under test, read again.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function reread(): Connection
    {
        return Connection::query()->whereKey($this->connection->id)->sole();
    }

    /**
     * Each violation of the result, by setting.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @return array<string, string>
     */
    private static function codes(ConnectionResult $result): array
    {
        $codes = [];

        foreach ($result->violations as $violation) {
            $codes[$violation->setting] = $violation->code->value;
        }

        return $codes;
    }

    /**
     * An OpenID Connect connection with linking on, classified and
     * acknowledged, its settings as the management helpers store them.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function openIdConnection(): Connection
    {
        return $this->stored('oidc', [
            'issuer'                 => 'https://idp.example.com',
            'authorization_endpoint' => 'https://idp.example.com/authorize',
            'token_endpoint'         => 'https://idp.example.com/token',
            'jwks_uri'               => 'https://idp.example.com/jwks',
            'client_id'              => 'client-1',
        ]);
    }

    /**
     * A SAML connection with linking on, classified and acknowledged, its
     * settings as the management helpers store them.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function samlConnection(): Connection
    {
        config()->set('sso.features.saml2', true);

        return $this->stored('saml2', ['idp_entity_id' => 'https://idp.example.com/saml', 'sso_url' => 'https://idp.example.com/sso'], [
            'linking_saml_attribute'        => 'email',
            'linking_saml_attribute_format' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        ]);
    }

    /**
     * A connection the management helpers created, with linking on, classified
     * and acknowledged.
     *
     * @param  string  $protocol
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $linking
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function stored(string $protocol, array $settings, array $linking = []): Connection
    {
        $created = app(ConnectionService::class)->create('tenant-1', $protocol, 'Acme', Clients::browser(), $settings);

        self::assertTrue($created->isChanged(), (string) json_encode($created->violations));

        $connection = Connection::query()->whereKey((string) $created->connection?->id)->sole();

        $connection->forceFill([
            'linking_enabled'         => true,
            'linking_issuer_class'    => 'single_organization',
            'linking_acknowledged_at' => CarbonImmutable::parse(self::ACKNOWLEDGED_AT),
            ...$linking,
        ])->save();

        return $connection;
    }
}
