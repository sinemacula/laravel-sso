<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for a SAML connection whose stored setting outlives the feature
 * that allows it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Saml2Driver::class)]
#[CoversClass(Saml2Settings::class)]
final class SamlFeatureSwitchTest extends TestCase
{
    use UsesConnections;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-saml';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection signed in through. */
    private Connection $connection;

    /** @var string The certificate the provider encrypts to. */
    private string $encryptionCertificate;

    /**
     * Configure SAML with both features on, and a connection that trusts the
     * provider and holds an encryption key.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, new RecordingFreshness);
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/assertions', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.encrypted_assertions', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'tenant_id'         => self::TENANT,
            'protocol'          => 'saml2',
            'enabled'           => true,
            'settings'          => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
            'attribute_mapping' => ['email' => 'email'],
        ]);

        $keys = app(KeyService::class);

        self::assertTrue($keys->trustCertificate(self::TENANT, $this->connection->id, self::idp()->certificate(), Clients::browser())->isSucceeded());

        $this->encryptionCertificate = (string) $keys->addNext(self::TENANT, $this->connection->id, KeyUse::SP_ENCRYPTION, Clients::browser())->key?->key->certificate;
    }

    /**
     * Rows of `[feature, settings]`: a setting on, and the feature it needs.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>}>
     */
    public static function provideGatedSettings(): iterable
    {
        yield 'encrypted assertions' => ['encrypted_assertions', ['require_encrypted_assertions' => true]];
        yield 'IdP-initiated' => ['idp_initiated', ['idp_initiated' => true, 'idp_initiated_start_url' => 'https://app.example.com/sso/start']];
    }

    /**
     * With the feature off, a start, an in-flight completion and a code
     * redemption are each `connection_unavailable`, and a plain assertion is
     * never accepted.
     *
     * @param  string  $feature
     * @param  array<string, mixed>  $settings
     * @return void
     */
    #[DataProvider('provideGatedSettings')]
    public function testTheFeatureTurnedOffMakesTheConnectionUnavailable(string $feature, array $settings): void
    {
        $this->connection->forceFill(['settings' => [...$this->connection->settings, ...$settings]])->save();

        $inFlight = $this->start();
        $issued   = $this->start();
        $handoff  = $this->complete($issued, true)->handoff;

        self::assertNotNull($handoff);

        config()->set('sso.features.' . $feature, false);

        $start = app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $this->connection->id, Clients::browser());

        self::assertSame([false, FailureReason::CONNECTION_UNAVAILABLE], [$start->isStarted(), $start->reason]);

        $completion = $this->complete($inFlight, false);

        self::assertSame([false, FailureReason::CONNECTION_UNAVAILABLE, null], [$completion->isCompleted(), $completion->reason, $completion->handoff]);
        self::assertSame(1, HandoffCode::query()->count());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->redeem($handoff->code->reveal(), $issued)->reason);
    }

    /**
     * Start a `sign_in` for `web`, the package generating the verifier.
     *
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function start(): StartResult
    {
        $start = app(AuthorizationRequestService::class)->start('web', Purpose::SIGN_IN, $this->connection->id, Clients::browser());

        self::assertTrue($start->isStarted());

        return $start;
    }

    /**
     * Have the provider answer the start, its assertion encrypted when asked,
     * and complete at the assertion consumer service.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  bool  $encrypted
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(StartResult $start, bool $encrypted): CompletionResult
    {
        $request  = self::idp()->receive($start);
        $response = self::idp()->respondTo($request, app(Clock::class)->now());

        return app(CompletionService::class)->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $this->connection->id,
            ($encrypted ? $response->encryptedFor($this->encryptionCertificate) : $response)->completionRequest($request->relayState),
            Clients::browser(),
        );
    }

    /**
     * Redeem the code as a `sign_in` for `web` with the start's verifier.
     *
     * @param  string  $code
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeem(string $code, StartResult $start): RedemptionResult
    {
        $verifier = (string) $start->verifier?->reveal();

        return DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => app(HandoffRedemption::class)->redeem(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, Clients::browser()),
        );
    }

    /**
     * The trusted identity provider, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
