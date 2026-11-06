<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\FetchedMetadata;
use SineMacula\Laravel\Sso\Metadata\RefreshClaim;
use SineMacula\Laravel\Sso\Metadata\SamlMetadataSource;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for what a SAML connection refreshes from (SSO-2.8, SSO-11.12):
 * which connections refresh, the snapshot and anchors its claim holds, the
 * fetch through the package's fetcher and its failures, a reader's exception
 * contained, and the write through the applier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SamlMetadataSource::class)]
final class SamlMetadataSourceTest extends TestCase
{
    use CapturesLogs, UsesConnections;

    /** @var string The URL the provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T09:30:00+00:00';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the source fetches through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and a fake fetcher serving the provider's metadata,
     * switch SAML on and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock   = new FixedClock(self::NOW);
        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', 'https://api.example.com');

        $this->usePackageTables();

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->toXml()));
    }

    /**
     * Rows of `[attributes, settings, refreshes]`: which connections refresh.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: bool}>
     */
    public static function provideConnections(): iterable
    {
        yield from [
            'its switch on and an https URL' => [[], [], true],
            'its switch off'                 => [[], ['metadata_refresh' => false], false],
            'its switch not true'            => [[], ['metadata_refresh' => 'true'], false],
            'no switch and an https URL'     => [[], ['metadata_refresh' => null], false],
            'no switch and no URL'           => [[], ['metadata_refresh' => null, 'metadata_url' => null], false],
            'an http URL'                    => [[], ['metadata_url' => 'http://idp.example.test/metadata.xml'], false],
            'no URL'                         => [[], ['metadata_url' => null], false],
            'a URL not a string'             => [[], ['metadata_url' => 1], false],
            'an OIDC connection'             => [['protocol' => 'oidc'], [], false],
        ];
    }

    /**
     * The schedule refreshes a connection that is SAML with a URL the package
     * may fetch and an explicit switch on; left unset with no anchor, it does
     * not.
     *
     * @param  array<string, mixed>  $attributes
     * @param  array<string, mixed>  $settings
     * @param  bool  $refreshes
     * @return void
     */
    #[DataProvider('provideConnections')]
    public function testWhichConnectionsRefresh(array $attributes, array $settings, bool $refreshes): void
    {
        self::assertSame('saml2', $this->source()->protocol());
        self::assertSame($refreshes, $this->source()->refreshes($this->saml($settings, $attributes)));
    }

    /**
     * Rows of `[anchored, switch, refreshes]`: with a URL, an anchor makes an
     * unset switch on, and `false` is off whatever the anchor.
     *
     * @return iterable<string, array{0: bool, 1: mixed, 2: bool}>
     */
    public static function provideAnchorsAndSwitches(): iterable
    {
        yield from [
            'an anchor, unset'    => [true, null, true],
            'an anchor, true'     => [true, true, true],
            'an anchor, false'    => [true, false, false],
            'no anchor, unset'    => [false, null, false],
            'no anchor, true'     => [false, true, true],
            'no anchor, false'    => [false, false, false],
            'an anchor, not true' => [true, 'true', false],
        ];
    }

    /**
     * Whether the schedule refreshes the connection, one at a time and as a due
     * listing judges it at once, for each anchor and switch.
     *
     * @param  bool  $anchored
     * @param  mixed  $switch
     * @param  bool  $refreshes
     * @return void
     */
    #[DataProvider('provideAnchorsAndSwitches')]
    public function testAnAnchorDecidesAnUnsetSwitch(bool $anchored, mixed $switch, bool $refreshes): void
    {
        $connection = $this->saml(['metadata_refresh' => $switch]);

        if ($anchored) {
            $this->trust($connection, Certificates::distinct(3), KeyUse::METADATA_SIGNING);
        }

        self::assertSame($refreshes, $this->source()->refreshes($connection));
        self::assertSame($refreshes ? [$connection->id] : [], array_map(static fn (Connection $listed): string => $listed->id, $this->source()->refreshing([$connection])));
    }

    /**
     * An anchor alone refreshes nothing with no URL, a certificate of another
     * use is no anchor, and a connection of another protocol is never judged.
     *
     * @return void
     */
    public function testAnAnchorNeedsAUrlAndToBeAnAnchor(): void
    {
        $noUrl = $this->saml(['metadata_refresh' => null, 'metadata_url' => null]);
        $idp   = $this->saml(['metadata_refresh' => null]);
        $oidc  = $this->saml(['metadata_refresh' => null], ['protocol' => 'oidc']);

        $this->trust($noUrl, Certificates::distinct(3), KeyUse::METADATA_SIGNING);
        $this->trust($idp, Certificates::distinct(4), KeyUse::IDP_SIGNING);
        $this->trust($oidc, Certificates::distinct(5), KeyUse::METADATA_SIGNING);

        self::assertSame([false, false, false], [$this->source()->refreshes($noUrl), $this->source()->refreshes($idp), $this->source()->refreshes($oidc)]);
        self::assertSame([], $this->source()->refreshing([$noUrl, $idp, $oidc]));
    }

    /**
     * What an administrator may refresh depends only on the protocol and the
     * URL, never the switch.
     *
     * @return void
     */
    public function testWhichConnectionsAreRefreshable(): void
    {
        self::assertTrue($this->source()->isRefreshable($this->saml(['metadata_refresh' => false])));
        self::assertTrue($this->source()->isRefreshable($this->saml(['metadata_refresh' => null])));
        self::assertFalse($this->source()->isRefreshable($this->saml(['metadata_url' => null])));
        self::assertFalse($this->source()->isRefreshable($this->saml(['metadata_url' => 'http://idp.example.test/metadata.xml'])));
        self::assertFalse($this->source()->isRefreshable($this->saml([], ['protocol' => 'oidc'])));
    }

    /**
     * The claim holds the sorted fingerprints of both uses and the anchors'
     * certificates, and writes its token; a second claim while it holds is
     * `null`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheClaimSnapshotsTheCertificatesAndAnchors(): void
    {
        $connection = $this->saml();
        $signing    = [$this->trust($connection, Certificates::distinct(1), KeyUse::IDP_SIGNING), $this->trust($connection, Certificates::distinct(2), KeyUse::IDP_SIGNING)];
        $anchor     = $this->trust($connection, Certificates::distinct(3), KeyUse::METADATA_SIGNING);
        $claim      = $this->source()->claim($connection);

        sort($signing);

        self::assertInstanceOf(RefreshClaim::class, $claim);
        self::assertSame([KeyUse::IDP_SIGNING->value => $signing, KeyUse::METADATA_SIGNING->value => [$anchor]], $claim->trusted);
        self::assertSame([MaskedKey::fromCertificate(Certificates::distinct(3))->certificate], $claim->anchors);
        self::assertSame($claim->token, $this->row($connection)->metadata_claim_token);
        self::assertNull($this->source()->claim($connection));
    }

    /**
     * A fetch reads the saved URL, held to the metadata cap, for the pinned
     * entity, with the moment it validated.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFetchReadsTheSavedUrlAndNotesWhenItValidated(): void
    {
        config()->set('sso.metadata.max_bytes', 70000);

        $fetched = $this->source()->fetch($this->claimOf($this->saml()));
        $request = $this->fetcher->requests()[0];

        self::assertSame([self::URL, FetchPurpose::METADATA, 70000], [$request->url, $request->purpose, $request->maxBytes]);
        self::assertInstanceOf(IdpMetadata::class, $fetched->document());
        self::assertSame([FetchStatus::FETCHED, null, self::NOW], [$fetched->fetchStatus, $fetched->reason, $fetched->validatedAt?->toIso8601String()]);
    }

    /**
     * Rows of `[response, reason, status]`: a fetch that brought no metadata.
     *
     * @return iterable<string, array{
     *     0: \SineMacula\Laravel\Sso\Fetching\FetchResult,
     *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason,
     *     2: \SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus
     * }>
     */
    public static function provideFailedFetches(): iterable
    {
        yield from [
            'refused'        => [FetchResult::refused(), FailureReason::FETCH_REFUSED, FetchStatus::REFUSED],
            'failed'         => [FetchResult::failed(), FailureReason::FETCH_FAILED, FetchStatus::FAILED],
            'a server error' => [FetchResult::fetched(503, [], 'down'), FailureReason::FETCH_FAILED, FetchStatus::FETCHED],
            'a redirect'     => [FetchResult::fetched(302, [], ''), FailureReason::FETCH_FAILED, FetchStatus::FETCHED],
            'not metadata'   => [FetchResult::fetched(200, [], '<html lang="en"></html>'), FailureReason::METADATA_INVALID, FetchStatus::FETCHED],
        ];
    }

    /**
     * Each is refused with its reason and the fetch's status, and with no
     * moment of validation.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus  $status
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideFailedFetches')]
    public function testAFailedFetchIsRefused(FetchResult $response, FailureReason $reason, FetchStatus $status): void
    {
        $this->fetcher->respond(self::URL, $response);

        $fetched = $this->source()->fetch($this->claimOf($this->saml()));

        self::assertSame([$reason, $status, null, null], [$fetched->reason, $fetched->fetchStatus, $fetched->validatedAt, $fetched->document()]);
    }

    /**
     * A reader that throws, rather than refusing the document, is contained as
     * invalid metadata and logged by its class alone.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAReaderThatThrowsIsContained(): void
    {
        $this->captureLogs();

        $this->fetcher->respond(self::URL, static function (): FetchResult {
            config()->set('sso.metadata.max_bytes', 'unreadable');

            return FetchResult::fetched(200, [], self::idp()->metadata()->toXml());
        });

        $fetched = $this->source()->fetch($this->claimOf($this->saml()));

        self::assertSame(FailureReason::METADATA_INVALID, $fetched->reason);
        self::assertNull($fetched->validatedAt);
        self::assertSame([[
            'channel' => 'sso_capture',
            'level'   => 'warning',
            'message' => 'sso.metadata.refresh_contained',
            'context' => ['exception' => \InvalidArgumentException::class],
        ]], $this->capturedLogRecords());
    }

    /**
     * A write of what was read applies it; a write of a refusal records the
     * failure with its reason.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testAWriteAppliesOrRecordsTheFailure(): void
    {
        $this->fetcher->respond(self::URL, FetchResult::failed());

        $failing = $this->saml();
        $claim   = $this->claimOf($failing);
        $failed  = $this->source()->write($claim, $this->source()->fetch($claim), null);

        self::assertSame([RefreshOutcome::FAILED, FailureReason::FETCH_FAILED, 1], [$failed->outcome, $failed->reason, $failed->failures]);

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->toXml()));

        $applying = $this->saml();

        $this->trust($applying, self::idp()->certificate(), KeyUse::IDP_SIGNING);

        $claim   = $this->claimOf($applying);
        $applied = $this->source()->write($claim, $this->source()->fetch($claim), null);

        self::assertSame([RefreshOutcome::REFRESHED, 1], [$applied->outcome, $applied->metadataVersion]);
        self::assertSame(self::NOW, $this->row($applying)->metadata_fetched_at?->toIso8601String());
    }

    /**
     * A write of what is not SAML metadata records the failure, as a read that
     * brought nothing does.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testAWriteOfAnotherDocumentRecordsAFailure(): void
    {
        $claim  = $this->claimOf($this->saml());
        $result = $this->source()->write($claim, FetchedMetadata::read(new \stdClass, $this->clock->now()), null);

        self::assertSame([RefreshOutcome::FAILED, FailureReason::METADATA_INVALID], [$result->outcome, $result->reason]);
    }

    /**
     * An anchor with no certificate is left out, and an anchor after it that
     * has one still judges the document: what it signed is read, and what it
     * did not sign is refused.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnAnchorWithNoCertificateIsLeftOut(): void
    {
        $connection = $this->saml();
        $empty      = $this->trust($connection, Certificates::distinct(7), KeyUse::METADATA_SIGNING);
        $aggregate  = ['aggregate' => ['https://other.example.test/saml'], 'sign' => 'aggregate'];

        ConnectionKey::query()->where('fingerprint', $empty)->update(['certificate' => null, 'created_at' => '2020-01-01 00:00:00']);

        $this->trust($connection, self::idp()->certificate(), KeyUse::METADATA_SIGNING);
        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->with($aggregate)->toXml()));

        $claim  = $this->claimOf($connection);
        $signed = $this->source()->fetch($claim);

        self::assertInstanceOf(IdpMetadata::class, $signed->document());
        self::assertSame([null, self::NOW], [$signed->reason, $signed->validatedAt?->toIso8601String()]);

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->toXml()));

        $unsigned = $this->source()->fetch($claim);

        self::assertNull($unsigned->document());
        self::assertSame(FailureReason::METADATA_SIGNATURE_INVALID, $unsigned->reason);
    }

    /**
     * The claim of the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshClaim
     *
     * @throws \Random\RandomException
     */
    private function claimOf(Connection $connection): RefreshClaim
    {
        $claim = $this->source()->claim($connection);

        self::assertInstanceOf(RefreshClaim::class, $claim);

        return $claim;
    }

    /**
     * A refreshing SAML connection holding the settings given, `null` removing
     * one, read back as stored.
     *
     * @param  array<string, mixed>  $settings
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $settings = [], array $attributes = []): Connection
    {
        $values = array_filter([
            'idp_entity_id'    => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'          => FakeSamlIdentityProvider::SSO_URL,
            'sso_binding'      => 'http_redirect',
            'metadata_url'     => self::URL,
            'metadata_refresh' => true,
            ...$settings,
        ], static fn (mixed $value): bool => $value !== null);

        return $this->row($this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => $values, ...$attributes]));
    }

    /**
     * Trust the certificate for the connection and the use; its fingerprint.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $certificate
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return string
     */
    private function trust(Connection $connection, string $certificate, KeyUse $use): string
    {
        $masked = MaskedKey::fromCertificate($certificate);

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => null,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'private_key'   => null,
            'fingerprint'   => $masked->fingerprint,
        ])->save();

        return (string) $masked->fingerprint;
    }

    /**
     * The connection as stored now, read on the write connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function row(Connection $connection): Connection
    {
        return Connection::query()->useWritePdo()->whereKey($connection->id)->firstOrFail();
    }

    /**
     * The source, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\SamlMetadataSource
     */
    private function source(): SamlMetadataSource
    {
        return app(SamlMetadataSource::class);
    }

    /**
     * The provider, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
