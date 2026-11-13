<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\CertificateInspector;
use SineMacula\Laravel\Sso\Keys\Enums\KeyStatus;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for the identity provider certificates a SAML connection
 * trusts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyService::class)]
#[CoversClass(CertificateInspector::class)]
final class TrustedCertificatesTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The tenant whose connection the helpers act on. */
    private const string TENANT = 'tenant-1';

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helpers ask. */
    private RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's SAML connection. */
    private Connection $connection;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock and recording freshness, create the tables and a SAML
     * connection, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;
        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);

        $this->startRecordingEvents();
    }

    /**
     * Rows of `[certificate, code]`: each certificate refused, and why.
     *
     * @return iterable<string, array{0: \Closure(): string, 1: string}>
     */
    public static function provideRefusedCertificates(): iterable
    {
        yield from [
            'malformed'                   => [static fn (): string => 'not a certificate', 'invalid_format'],
            'a private key'               => [static fn (): string => Certificates::privateKey(), 'private_key_refused'],
            'too long'                    => [static fn (): string => str_repeat('A', 16385), 'too_long'],
            'a weak rsa 1024 key'         => [static fn (): string => Certificates::rsa1024(), 'weak_key'],
            'a curve the package refuses' => [static fn (): string => Certificates::unsupportedCurve(), 'weak_key'],
            'an ed25519 key'              => [static fn (): string => Certificates::ED25519, 'not_allowed'],
            'an ec p-256 key'             => [static fn (): string => Certificates::ecP256(), 'unsupported'],
            'an ec p-384 key'             => [static fn (): string => Certificates::ecP384(), 'unsupported'],
        ];
    }

    /**
     * Each refused certificate is invalid at `certificate`, before freshness is
     * asked.
     *
     * @param  \Closure(): string  $certificate
     * @param  string  $code
     * @return void
     */
    #[DataProvider('provideRefusedCertificates')]
    public function testRefusesEachCertificateWithItsCode(\Closure $certificate, string $code): void
    {
        $result = $this->trust($certificate());

        self::assertTrue($result->isInvalid());
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame([['setting' => 'certificate', 'code' => $code]], $result->jsonSerialize()['violations']);
        self::assertSame([], $this->freshness->asked());
        self::assertSame(0, ConnectionKey::query()->count());
        $this->assertNoEvents();
    }

    /**
     * Rows of `[certificate, type, bits]` for each trusted certificate.
     *
     * @return iterable<string, array{0: \Closure(): string, 1: \SineMacula\Laravel\Sso\Keys\Enums\KeyType, 2: int}>
     */
    public static function provideTrustedCertificates(): iterable
    {
        yield from [
            'rsa 2048'   => [static fn (): string => Certificates::rsa2048(), KeyType::RSA, 2048],
            'rsa 2048 b' => [static fn (): string => Certificates::distinct(0), KeyType::RSA, 2048],
        ];
    }

    /**
     * An accepted certificate is stored with no state or private key,
     * summarised and reported as added.
     *
     * @param  \Closure(): string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  int  $bits
     * @return void
     */
    #[DataProvider('provideTrustedCertificates')]
    public function testTrustsAnAcceptedCertificate(\Closure $certificate, KeyType $type, int $bits): void
    {
        $pem    = $certificate();
        $result = $this->trust($pem);
        $key    = self::summaryOf($result);

        self::assertSame(KeyStatus::TRUSTED, $result->status);
        self::assertTrue($result->isSucceeded());
        self::assertSame(KeyUse::IDP_SIGNING, $key->use);
        self::assertNull($key->state);
        self::assertSame($type, $key->type);
        self::assertSame($bits, $key->bits);
        self::assertSame(MaskedKey::fromCertificate($pem)->certificate, $key->key->certificate);
        self::assertSame(openssl_x509_fingerprint($pem, 'sha256'), $key->key->fingerprint);
        self::assertNull($key->madeCurrentAt);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, 300]], $this->freshness->asked());

        $row = ConnectionKey::query()->findOrFail($key->id);

        self::assertNull($row->state);
        self::assertNull($row->private_key);
        self::assertSame($bits, $row->key_bits);

        $this->assertEventSequence([KeyAdded::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyAdded::class, $event);
        self::assertSame($key->id, $event->keyId);
        self::assertSame(KeyUse::IDP_SIGNING, $event->use);
        self::assertNull($event->state);
    }

    /**
     * The connection trusts a set, oldest first.
     *
     * @return void
     */
    public function testTrustsASet(): void
    {
        $first  = self::summaryOf($this->trust(Certificates::rsa2048()));
        $second = self::summaryOf($this->trust(Certificates::distinct(0)));

        self::assertSame([$first->id, $second->id], array_map(static fn (KeySummary $key): string => $key->id, $this->ring()->trustedCertificates($this->connection->id)));
    }

    /**
     * A certificate already trusted is a duplicate, however its PEM is laid
     * out.
     *
     * @return void
     */
    public function testRefusesADuplicate(): void
    {
        $this->trust(Certificates::distinct(0));
        $this->freshness->reset();
        $this->startRecordingEvents();

        $result = $this->trust("\r\n" . str_replace("\n", "\r\n", Certificates::distinct(0)));

        self::assertTrue($result->isInvalid());
        self::assertSame([['setting' => 'certificate', 'code' => 'duplicate']], $result->jsonSerialize()['violations']);
        self::assertSame([], $this->freshness->asked());
        self::assertSame(1, ConnectionKey::query()->count());
        $this->assertNoEvents();
    }

    /**
     * Another connection may trust the same certificate.
     *
     * @return void
     */
    public function testAnotherConnectionMayTrustTheSameCertificate(): void
    {
        $other = $this->makeConnection(['protocol' => 'saml2']);

        $this->trust(Certificates::distinct(0));

        self::assertTrue($this->keys()->trustCertificate(self::TENANT, $other->id, Certificates::distinct(0), Clients::browser())->isSucceeded());
    }

    /**
     * A connection trusts at most ten certificates until one is removed.
     *
     * @return void
     */
    public function testTrustsAtMostTenCertificates(): void
    {
        $trusted = [];

        for ($index = 1; $index <= KeyService::MAX_TRUSTED_CERTIFICATES; $index++) {
            $trusted[] = self::summaryOf($this->trust(Certificates::distinct($index)));
        }

        $this->startRecordingEvents();

        $result = $this->trust(Certificates::distinct(11));

        self::assertSame(10, KeyService::MAX_TRUSTED_CERTIFICATES);
        self::assertTrue($result->isInvalid());
        self::assertSame([['setting' => 'certificate', 'code' => 'too_many']], $result->jsonSerialize()['violations']);
        self::assertSame(10, ConnectionKey::query()->count());
        $this->assertNoEvents();

        $this->keys()->distrustCertificate(self::TENANT, $this->connection->id, $trusted[0]->id, Clients::browser());

        self::assertTrue($this->trust(Certificates::distinct(11))->isSucceeded());
    }

    /**
     * A connection's own keys do not count towards the cap.
     *
     * @return void
     */
    public function testOwnKeysDoNotCountTowardsTheCap(): void
    {
        $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA);

        for ($index = 1; $index <= KeyService::MAX_TRUSTED_CERTIFICATES; $index++) {
            self::assertTrue($this->trust(Certificates::distinct($index))->isSucceeded());
        }
    }

    /**
     * An OIDC connection trusts no certificate: its keys come from the JWKS.
     *
     * @return void
     */
    public function testAnOidcConnectionIsRefused(): void
    {
        $oidc   = $this->makeConnection(['protocol' => 'oidc']);
        $result = $this->keys()->trustCertificate(self::TENANT, $oidc->id, Certificates::distinct(0), Clients::browser());

        self::assertTrue($result->isInvalid());
        self::assertSame([['setting' => 'certificate', 'code' => 'unsupported']], $result->jsonSerialize()['violations']);
        self::assertSame([], $this->freshness->asked());
        self::assertSame(0, ConnectionKey::query()->count());
    }

    /**
     * An expired certificate is trusted and still offered by the key ring.
     *
     * @return void
     */
    public function testTrustsAnExpiredCertificate(): void
    {
        $pem      = Certificates::rsaOneDay();
        $notAfter = openssl_x509_parse($pem)['validTo_time_t'] ?? null;

        self::assertIsInt($notAfter);

        $clock = new FixedClock(CarbonImmutable::createFromTimestamp($notAfter, 'UTC')->addYears(2)->toIso8601String());

        $this->app?->instance(Clock::class, $clock);

        $key = self::summaryOf($this->trust($pem));

        self::assertTrue($key->isExpiredAt($clock->now()));
        self::assertSame($notAfter, $key->notAfter?->getTimestamp());
        self::assertSame([$key->id], array_map(static fn (KeySummary $trusted): string => $trusted->id, $this->ring()->trustedCertificates($this->connection->id)));
    }

    /**
     * A trusted certificate, the last included, is distrusted, removed and
     * reported as retired.
     *
     * @return void
     */
    public function testDistrustsACertificateTheLastIncluded(): void
    {
        $first  = self::summaryOf($this->trust(Certificates::rsa2048()));
        $second = self::summaryOf($this->trust(Certificates::distinct(0)));

        $this->freshness->reset();
        $this->startRecordingEvents();

        $result = $this->keys()->distrustCertificate(
            self::TENANT,
            $this->connection->id,
            $first->id,
            Clients::browser(),
            new Caller(new IdentityReference('App\Models\User', '42')),
        );
        $key = self::summaryOf($result);

        self::assertSame(KeyStatus::DISTRUSTED, $result->status);
        self::assertSame($first->id, $key->id);
        self::assertSame($first->key->fingerprint, $key->key->fingerprint);
        self::assertSame([[FreshnessOperation::CONNECTION_TRUST, 300]], $this->freshness->asked());
        self::assertNull(ConnectionKey::query()->find($first->id));

        $this->assertEventSequence([KeyRetired::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(KeyRetired::class, $event);
        self::assertSame($first->id, $event->keyId);
        self::assertSame(KeyUse::IDP_SIGNING, $event->use);
        self::assertSame('42', $event->context->actingIdentityId);

        self::assertTrue($this->keys()->distrustCertificate(self::TENANT, $this->connection->id, $second->id, Clients::browser())->isSucceeded());
        self::assertSame([], $this->ring()->trustedCertificates($this->connection->id));
    }

    /**
     * Only the connection's trusted certificates can be distrusted; anything
     * else is not found.
     *
     * @return void
     */
    public function testDistrustsOnlyTheConnectionsCertificates(): void
    {
        $other  = $this->makeConnection(['protocol' => 'saml2']);
        $own    = self::summaryOf($this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA));
        $theirs = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $other->id, Certificates::distinct(0), Clients::browser()));

        $this->freshness->reset();
        $this->startRecordingEvents();

        foreach ([$own->id, $theirs->id, '01jbunknownkey000000000000', ''] as $keyId) {
            self::assertSame(FailureReason::KEY_NOT_FOUND, $this->keys()->distrustCertificate(self::TENANT, $this->connection->id, $keyId, Clients::browser())->reason);
        }

        self::assertSame([], $this->freshness->asked());
        self::assertSame(2, ConnectionKey::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A certificate trusted between the first read and the transaction makes
     * the second a duplicate.
     *
     * @return void
     */
    public function testACertificateTrustedMeanwhileIsADuplicate(): void
    {
        $this->beforeTheNextTransaction(fn (): mixed => $this->trust(Certificates::distinct(0)));

        $result = $this->trust(Certificates::distinct(0));

        self::assertSame([['setting' => 'certificate', 'code' => 'duplicate']], $result->jsonSerialize()['violations']);
        self::assertSame(1, ConnectionKey::query()->count());
    }

    /**
     * Trusting a signing certificate is additive: it voids nothing and keeps
     * the trust version.
     *
     * @return void
     */
    public function testTrustingASigningCertificateVoidsNothing(): void
    {
        $pending = $this->makeAuthorizationRequest($this->connection, ['consumed_at' => $this->clock->now()]);
        $code    = $this->makeHandoffCode($this->connection);

        $this->clock->advance(60);

        self::assertTrue($this->trust(Certificates::distinct(0))->isSucceeded());

        self::assertNull(AuthorizationRequest::query()->findOrFail($pending->id)->voided_at);
        self::assertNull(HandoffCode::query()->findOrFail($code->id)->voided_at);
        self::assertSame(0, Connection::query()->findOrFail($this->connection->id)->trust_version);
    }

    /**
     * Trusting a metadata signing anchor voids the connection's unfinished
     * requests and codes and raises its trust version.
     *
     * @return void
     */
    public function testTrustingAMetadataAnchorVoidsWhatIsInFlight(): void
    {
        $other    = $this->makeConnection(['protocol' => 'saml2']);
        $pending  = $this->makeAuthorizationRequest($this->connection, ['consumed_at' => $this->clock->now()]);
        $finished = $this->makeAuthorizationRequest($this->connection, ['consumed_at' => $this->clock->now(), 'completed_at' => $this->clock->now()]);
        $code     = $this->makeHandoffCode($this->connection);
        $redeemed = $this->makeHandoffCode($this->connection, ['redeemed_at' => $this->clock->now()]);
        $theirs   = $this->makeAuthorizationRequest($other);

        $this->clock->advance(60);

        $result = $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser(), null, KeyUse::METADATA_SIGNING);

        self::assertSame(KeyUse::METADATA_SIGNING, self::summaryOf($result)->use);
        self::assertSame('2026-11-01T09:31:00+00:00', AuthorizationRequest::query()->findOrFail($pending->id)->voided_at?->toIso8601String());
        self::assertSame('2026-11-01T09:31:00+00:00', HandoffCode::query()->findOrFail($code->id)->voided_at?->toIso8601String());
        self::assertNull(AuthorizationRequest::query()->findOrFail($finished->id)->voided_at);
        self::assertNull(HandoffCode::query()->findOrFail($redeemed->id)->voided_at);
        self::assertNull(AuthorizationRequest::query()->findOrFail($theirs->id)->voided_at);
        self::assertSame([1, 0], [Connection::query()->findOrFail($this->connection->id)->trust_version, Connection::query()->findOrFail($other->id)->trust_version]);
    }

    /**
     * Metadata signing anchors are a separately capped set, and the key ring
     * answers each set alone.
     *
     * @return void
     */
    public function testAnchorsAreASetOfTheirOwn(): void
    {
        $signing = self::summaryOf($this->trust(Certificates::distinct(0)));
        $anchor  = self::summaryOf(
            $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser(), null, KeyUse::METADATA_SIGNING),
        );
        $ring = app(KeyRing::class);

        self::assertSame([$signing->id], array_map(static fn (KeySummary $key): string => $key->id, $ring->trustedCertificates($this->connection->id)));
        self::assertSame([$anchor->id], array_map(static fn (KeySummary $key): string => $key->id, $ring->trustedCertificates($this->connection->id, KeyUse::METADATA_SIGNING)));
        $again = $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser(), null, KeyUse::METADATA_SIGNING);

        self::assertSame([['setting' => 'certificate', 'code' => 'duplicate']], $again->jsonSerialize()['violations']);
    }

    /**
     * SAML is RSA only: an EC certificate is refused as `unsupported` for every
     * use.
     *
     * @return void
     */
    public function testAnEllipticCurveCertificateIsRefusedForEverySamlUse(): void
    {
        foreach ([KeyUse::IDP_SIGNING, KeyUse::METADATA_SIGNING] as $use) {
            foreach ([Certificates::ecP256(), Certificates::ecP384()] as $certificate) {

                $result = $this->keys()->trustCertificate(self::TENANT, $this->connection->id, $certificate, Clients::browser(), null, $use);

                $refusal = [$result->reason, $result->jsonSerialize()['violations']];

                self::assertSame([FailureReason::SETTINGS_INVALID, [['setting' => 'certificate', 'code' => 'unsupported']]], $refusal);
            }
        }

        self::assertSame([], $this->freshness->asked());
        self::assertSame(0, ConnectionKey::query()->count());
    }

    /**
     * Only a trusted certificate's use may be trusted, and the key ring answers
     * only those.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyATrustedCertificatesUseIsTrusted(): void
    {
        try {
            $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser(), null, KeyUse::SP_SIGNING);
            self::fail('An own key\'s use was trusted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A certificate is trusted as [idp_signing] or [metadata_signing], never as [sp_signing].', $exception->getMessage());
        }

        $this->expectExceptionObject(new \InvalidArgumentException('[sp_encryption] is not a use of a trusted certificate.'));

        app(KeyRing::class)->trustedCertificates($this->connection->id, KeyUse::SP_ENCRYPTION);
    }

    /**
     * Distrusting a certificate voids what is in flight and raises the trust
     * version.
     *
     * @return void
     */
    public function testDistrustingACertificateVoidsWhatIsInFlight(): void
    {
        $certificate = self::summaryOf($this->trust(Certificates::distinct(0)));
        $request     = $this->makeAuthorizationRequest($this->connection);
        $code        = $this->makeHandoffCode($this->connection);

        $this->clock->advance(60);

        self::assertTrue($this->keys()->distrustCertificate(self::TENANT, $this->connection->id, $certificate->id, Clients::browser())->isSucceeded());

        self::assertSame('2026-11-01T09:31:00+00:00', AuthorizationRequest::query()->findOrFail($request->id)->voided_at?->toIso8601String());
        self::assertSame('2026-11-01T09:31:00+00:00', HandoffCode::query()->findOrFail($code->id)->voided_at?->toIso8601String());
        self::assertSame(1, Connection::query()->findOrFail($this->connection->id)->trust_version);
    }

    /**
     * A refused change voids nothing: a duplicate, a stale caller or a missing
     * certificate.
     *
     * @return void
     */
    public function testARefusedCertificateChangeVoidsNothing(): void
    {
        $this->trust(Certificates::distinct(0));

        $request = $this->makeAuthorizationRequest($this->connection);
        $code    = $this->makeHandoffCode($this->connection);

        self::assertTrue($this->trust(Certificates::distinct(0))->isInvalid());
        self::assertSame(
            FailureReason::KEY_NOT_FOUND,
            $this->keys()->distrustCertificate(self::TENANT, $this->connection->id, '01jbunknownkey000000000000', Clients::browser())->reason,
        );

        $this->freshness->answer(FreshnessOutcome::STALE);

        self::assertTrue($this->trust(Certificates::rsa2048())->isRefused());

        self::assertNull(AuthorizationRequest::query()->findOrFail($request->id)->voided_at);
        self::assertNull(HandoffCode::query()->findOrFail($code->id)->voided_at);
    }

    /**
     * Trust the certificate for the tenant's connection.
     *
     * @param  string  $certificate
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     */
    private function trust(string $certificate): KeyResult
    {
        return $this->keys()->trustCertificate(self::TENANT, $this->connection->id, $certificate, Clients::browser());
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
     * The key ring, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyRing
     */
    private function ring(): KeyRing
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyRing::class);
    }

    /**
     * The summary the result carries, which it must.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyResult  $result
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private static function summaryOf(KeyResult $result): KeySummary
    {
        self::assertNotNull($result->key, sprintf('The helper answered %s (%s).', $result->status->value, $result->reason->value ?? 'no reason'));

        return $result->key;
    }
}
