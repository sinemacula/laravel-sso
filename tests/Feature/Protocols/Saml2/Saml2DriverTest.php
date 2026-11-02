<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for the SAML driver's own part (SSO-2.1, SSO-2.3, SSO-2.8): it
 * is built from the container and reads SAML settings; a connection is complete
 * only with its settings complete, a trusted signing certificate and each
 * current key its settings need; and a start, a completion and a re-initiation
 * are refused with `metadata_expired`, before any collaborator is asked, while
 * what a metadata refresh applied has expired.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Saml2Driver::class)]
final class Saml2DriverTest extends TestCase
{
    use UsesConnections;

    /** @var array<string, string> Complete settings. */
    private const array SETTINGS = ['idp_entity_id' => 'https://idp.example.com/entity', 'sso_url' => 'https://idp.example.com/sso'];

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock, configure SAML and the endpoints, and create the
     * tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->createConnectionTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * The manager builds the driver from the container, and the driver reads
     * SAML settings.
     *
     * @return void
     */
    public function testIsBuiltFromTheContainerAndReadsSamlSettings(): void
    {
        $driver = app(ProtocolManager::class)->protocol(Saml2Driver::NAME);

        self::assertInstanceOf(Saml2Driver::class, $driver);
        self::assertSame('saml2', Saml2Driver::NAME);
        self::assertInstanceOf(Saml2Settings::class, $driver->settings(['sso_url' => 'https://idp.example.com/sso']));
        self::assertSame('https://idp.example.com/sso', $driver->settings(['sso_url' => 'https://idp.example.com/sso'])->toArray()['sso_url']);
    }

    /**
     * Rows of `[settings, keys, complete]`: a connection's settings, the keys
     * and certificates it holds, and whether it is complete.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<array{0: \SineMacula\Laravel\Sso\Keys\Enums\KeyUse, 1: mixed}>, 2: bool}>
     */
    public static function provideCompleteness(): iterable
    {
        $trusted    = [KeyUse::IDP_SIGNING, null];
        $signing    = [KeyUse::SP_SIGNING, KeyState::CURRENT];
        $encryption = [KeyUse::SP_ENCRYPTION, KeyState::CURRENT];
        $signed     = [...self::SETTINGS, 'sign_authn_requests' => true];
        $encrypted  = [...self::SETTINGS, 'require_encrypted_assertions' => true];
        $both       = [...$signed, 'require_encrypted_assertions' => true];

        yield from [
            'incomplete settings'                     => [['idp_entity_id' => 'https://idp.example.com/entity'], [$trusted], false],
            'no trusted certificate'                  => [self::SETTINGS, [], false],
            'only an anchor'                          => [self::SETTINGS, [[KeyUse::METADATA_SIGNING, null]], false],
            'a trusted certificate'                   => [self::SETTINGS, [$trusted], true],
            'signed requests with no key'             => [$signed, [$trusted], false],
            'signed requests with only a next key'    => [$signed, [$trusted, [KeyUse::SP_SIGNING, KeyState::NEXT]], false],
            'signed requests with a current key'      => [$signed, [$trusted, $signing], true],
            'encrypted assertions with no key'        => [$encrypted, [$trusted, $signing], false],
            'encrypted assertions with a current key' => [$encrypted, [$trusted, $encryption], true],
            'both, with only the encryption key'      => [$both, [$trusted, $encryption], false],
            'both, with both keys'                    => [$both, [$trusted, $signing, $encryption], true],
        ];
    }

    /**
     * A connection is complete only with its settings complete, a trusted
     * signing certificate, and each current key its settings need.
     *
     * @param  array<string, mixed>  $settings
     * @param  list<array{0: \SineMacula\Laravel\Sso\Keys\Enums\KeyUse, 1: ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState}>  $keys
     * @param  bool  $complete
     * @return void
     */
    #[DataProvider('provideCompleteness')]
    public function testIsCompleteOnlyWithEverythingItsSettingsNeed(array $settings, array $keys, bool $complete): void
    {
        config()->set('sso.features.encrypted_assertions', true);

        $connection = $this->saml($settings);

        foreach ($keys as $index => [$use, $state]) {
            $this->key($connection, $use, $state, $index);
        }

        self::assertSame($complete, $this->driver()->isComplete($connection));
    }

    /**
     * A start, a completion and a re-initiation are refused with
     * `metadata_expired` once what a refresh applied expires, and go on to
     * their collaborator until then.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFlowIsRefusedOnceTheMetadataExpires(): void
    {
        $settings   = [...self::SETTINGS, 'metadata_url' => 'https://idp.example.test/metadata.xml', 'metadata_refresh' => true];
        $connection = $this->saml($settings, ['metadata_fetched_at' => $this->clock->now(), 'metadata_valid_until' => $this->clock->now()->addHour()]);

        self::assertSame([false, false, false], $this->expiredAnswers($connection));

        $this->clock->advance(3599);

        self::assertSame([false, false, false], $this->expiredAnswers($connection));

        $this->clock->advance(1);

        self::assertSame([true, true, true], $this->expiredAnswers($connection));
    }

    /**
     * A connection no refresh has written never expires, and the driver reads
     * which request a response answers through its correlator.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAConnectionNoRefreshWroteNeverExpires(): void
    {
        $connection = $this->saml(self::SETTINGS);

        $this->clock->advance(86400 * 365);

        self::assertSame([false, false, false], $this->expiredAnswers($connection));
        self::assertTrue($this->driver()->correlate($connection, new CompletionRequest('POST', '', []))->isUncorrelated());
    }

    /**
     * The start URL re-initiation sends the browser to names the connection
     * while it allows IdP-initiated sign-in, and is `null` once it does not.
     *
     * @return void
     */
    public function testTheStartUrlIsTheConnectionsWhileItAllowsIdpInitiatedSignIn(): void
    {
        config()->set('sso.features.idp_initiated', true);

        $allowed = $this->saml([...self::SETTINGS, 'idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/start']);
        $refused = $this->saml([...self::SETTINGS, 'idp_initiated' => false, 'idp_initiated_start_url' => 'https://app.example.com/start']);

        self::assertSame('https://app.example.com/start?connection=' . $allowed->id, $this->driver()->startUrl($allowed));
        self::assertNull($this->driver()->startUrl($refused));
    }

    /**
     * Whether a start, a completion and a re-initiation through the connection
     * were each refused with `metadata_expired`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return list<bool>
     *
     * @throws \Random\RandomException
     */
    private function expiredAnswers(Connection $connection): array
    {
        $driver    = $this->driver();
        $reference = RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456');
        $request   = new CompletionRequest('POST', '', []);
        $start     = $driver->start($connection, new StartRequest(Purpose::SIGN_IN, 'web', $reference, new Secret('state')));
        $complete  = $driver->complete($connection, $request, new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, CarbonImmutable::now()));
        $unsolicit = $driver->reinitiate($connection, $request);

        $reasons = [$start->reason, $complete->reason, $unsolicit->reason];

        return array_map(static fn (?FailureReason $reason): bool => $reason === FailureReason::METADATA_EXPIRED, $reasons);
    }

    /**
     * The driver, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver
     */
    private function driver(): Saml2Driver
    {
        return app(Saml2Driver::class);
    }

    /**
     * A SAML connection with the settings and attributes given.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $settings, array $attributes = []): Connection
    {
        return $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => $settings, ...$attributes]);
    }

    /**
     * Store a key or certificate of the use and state for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  int  $index
     * @return void
     */
    private function key(Connection $connection, KeyUse $use, ?KeyState $state, int $index): void
    {
        $certificate = Certificates::distinct($index);
        $public      = openssl_pkey_get_public($certificate);

        self::assertNotFalse($public);

        $details = openssl_pkey_get_details($public);

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => $state,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'private_key'   => $use->isOwnKey() ? 'ciphertext' : null,
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();
    }
}
