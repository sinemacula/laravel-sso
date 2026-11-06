<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\Eloquent\MassAssignmentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\SsoModel;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the connection model (SSO-2.1): its table and connection,
 * its ULID key and clock timestamps, its defaults, its casts, the contract it
 * answers through, its hidden secrets, and its tenant and protocol fixed at
 * creation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Connection::class)]
#[CoversClass(SsoModel::class)]
final class ConnectionTest extends TestCase
{
    use UsesConnections;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        $this->usePackageTables();
    }

    /**
     * The model takes its configured table on the storage connection.
     *
     * @return void
     */
    public function testTakesItsTableAndConnection(): void
    {
        self::assertSame('sso_connections', (new Connection)->getTable());
        self::assertNull((new Connection)->getConnectionName());

        config()->set('sso.connections.table', 'idp_connections');
        config()->set('sso.storage.connection', 'package_store');

        self::assertSame('idp_connections', (new Connection)->getTable());
        self::assertSame('package_store', (new Connection)->getConnectionName());
    }

    /**
     * A new connection gets a lower-case ULID and is stamped from the package's
     * clock, in UTC; an update stamps only `updated_at`.
     *
     * @return void
     */
    public function testIsKeyedByAUlidAndStampedByTheClock(): void
    {
        $connection = $this->makeConnection();

        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/', $connection->id);
        self::assertSame('2026-11-01T09:30:00Z', $connection->created_at->format('Y-m-d\TH:i:s\Z'));
        self::assertSame('2026-11-01 09:30:00', $connection->getRawOriginal('created_at'));

        $this->clock->advance(90);

        $connection->forceFill(['display_name' => 'Renamed'])->save();

        $fresh = Connection::query()->findOrFail($connection->id);

        self::assertSame('2026-11-01 09:30:00', $fresh->getRawOriginal('created_at'));
        self::assertSame('2026-11-01 09:31:30', $fresh->getRawOriginal('updated_at'));
        self::assertNotSame($connection->id, $this->makeConnection()->id);
    }

    /**
     * A new connection is disabled, has completed no sign-in, and has no
     * settings or mapping.
     *
     * @return void
     */
    public function testANewConnectionHasTheSafeDefaults(): void
    {
        $connection = Connection::query()->findOrFail($this->makeConnection()->id);

        self::assertFalse($connection->enabled);
        self::assertFalse($connection->has_completed_sign_in);
        self::assertSame([], $connection->settings);
        self::assertSame([], $connection->attribute_mapping);
        self::assertNull($connection->secrets);
    }

    /**
     * The connection answers its contract from its columns, with no secret.
     *
     * @return void
     */
    public function testAnswersItsContractFromItsColumns(): void
    {
        $connection = $this->makeConnection([
            'tenant_id'             => 'tenant-9',
            'protocol'              => 'saml2',
            'display_name'          => 'Acme IdP',
            'settings'              => ['idp_entity_id' => 'https://idp.acme.example', 'sign_authn_requests' => true],
            'secrets'               => 'ciphertext',
            'attribute_mapping'     => ['email' => 'mail'],
            'enabled'               => true,
            'has_completed_sign_in' => true,
        ]);

        $read = Connection::query()->findOrFail($connection->id);

        self::assertInstanceOf(SsoConnection::class, $read);
        self::assertSame($connection->id, $read->getConnectionId());
        self::assertSame('tenant-9', $read->getTenantId());
        self::assertSame('saml2', $read->getProtocol());
        self::assertSame('Acme IdP', $read->getDisplayName());
        self::assertSame(['idp_entity_id' => 'https://idp.acme.example', 'sign_authn_requests' => true], $read->getSettings());
        self::assertSame(['email' => 'mail'], $read->getAttributeMapping());
        self::assertTrue($read->isEnabled());
        self::assertTrue($read->hasCompletedSignIn());
    }

    /**
     * The connection answers its linking settings from its columns, under
     * exactly these names; the moment of its acknowledgement shows only as
     * whether there is one.
     *
     * @return void
     */
    public function testAnswersItsLinkingSettingsFromItsColumns(): void
    {
        $connection = $this->makeConnection([
            'linking_enabled'               => true,
            'linking_issuer_class'          => 'shared',
            'linking_organization_claim'    => 'org',
            'linking_organization_value'    => 'acme',
            'linking_saml_attribute'        => 'mail',
            'linking_saml_attribute_format' => 'urn:example:format',
            'linking_acknowledged_at'       => $this->clock->now(),
            'linking_version'               => 3,
        ]);

        self::assertSame([
            'enabled'               => true,
            'issuer_class'          => 'shared',
            'organization_claim'    => 'org',
            'organization_value'    => 'acme',
            'saml_attribute'        => 'mail',
            'saml_attribute_format' => 'urn:example:format',
            'acknowledged'          => true,
            'version'               => 3,
        ], $connection->getLinkingSettings());

        $connection->forceFill(['linking_acknowledged_at' => null]);

        self::assertFalse($connection->getLinkingSettings()['acknowledged']);
    }

    /**
     * The encrypted secrets are hidden from serialisation.
     *
     * @return void
     */
    public function testHidesTheSecrets(): void
    {
        $connection = $this->makeConnection(['secrets' => 'ciphertext']);

        self::assertArrayNotHasKey('secrets', $connection->toArray());
        self::assertStringNotContainsString('ciphertext', (string) json_encode($connection));
    }

    /**
     * A column holding what is no policy reads as none: never a type error.
     *
     * @return void
     */
    public function testAnEvidencePolicyThatIsNoPolicyReadsAsNone(): void
    {
        $connection = new Connection;

        foreach ([[null, []], ['5', []], ['"amr"', []], ['true', []], ['not json', []], ['{"amr":["pwd"]}', ['amr' => ['pwd']]]] as [$column, $expected]) {
            $connection->setRawAttributes(['evidence_policy' => $column]);

            self::assertSame($expected, $connection->getEvidencePolicy());
        }
    }

    /**
     * The organisation a linking result must assert is hidden from
     * serialisation too, and stays readable to the linking settings.
     *
     * @return void
     */
    public function testHidesTheLinkingOrganizationValue(): void
    {
        $connection = $this->makeConnection();

        $connection->forceFill(['linking_organization_value' => 'acme.example']);

        self::assertArrayNotHasKey('linking_organization_value', $connection->toArray());
        self::assertStringNotContainsString('acme.example', (string) json_encode($connection));
        self::assertSame('acme.example', $connection->getLinkingSettings()['organization_value']);
    }

    /**
     * Rows of `[column, value]`: the columns fixed at creation, and a value
     * each could be changed to.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideFixedColumns(): iterable
    {
        yield from [
            'the tenant'   => ['tenant_id', 'tenant-2'],
            'the protocol' => ['protocol', 'saml2'],
        ];
    }

    /**
     * Changing the tenant or the protocol once the connection exists throws,
     * and nothing is written.
     *
     * @param  string  $column
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideFixedColumns')]
    public function testTheTenantAndProtocolAreFixed(string $column, string $value): void
    {
        $connection = $this->makeConnection();
        $copy       = Connection::query()->findOrFail($connection->id);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A connection\'s tenant and protocol are fixed when it is created.');

        try {
            $copy->forceFill([$column => $value, 'display_name' => 'Changed'])->save();
        } finally {
            $read = Connection::query()->findOrFail($connection->id);

            self::assertSame(['tenant-1', 'oidc', 'Example'], [$read->tenant_id, $read->protocol, $read->display_name]);
        }
    }

    /**
     * Every column but the tenant and the protocol changes.
     *
     * @return void
     */
    public function testEveryOtherColumnChanges(): void
    {
        $connection = $this->makeConnection();

        $connection->forceFill(['display_name' => 'Changed', 'enabled' => true, 'settings' => ['a' => 1]])->save();

        $read = Connection::query()->findOrFail($connection->id);

        self::assertSame(['Changed', true, ['a' => 1]], [$read->display_name, $read->enabled, $read->settings]);
    }

    /**
     * No attribute is mass assignable.
     *
     * @return void
     */
    public function testNothingIsMassAssignable(): void
    {
        $this->expectException(MassAssignmentException::class);

        Connection::query()->create(['tenant_id' => 'tenant-1']);
    }
}
