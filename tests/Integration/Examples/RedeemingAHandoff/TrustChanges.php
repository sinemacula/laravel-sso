<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Integration\Examples\Clients;

/**
 * The changes an administrator, or the metadata refresh, makes to a SAML
 * connection's trust between a code's issuance and its redemption (SSO-2.13),
 * through the package's public API alone: the provider's certificates replaced
 * by a refresh of its metadata, one of two trusted certificates distrusted, a
 * metadata signing anchor trusted, and the connection disabled then enabled
 * again. Each raises the connection's trust version, and leaves it usable,
 * signed for by the provider each answers; adding a provider certificate alone
 * is additive, and raises nothing.
 *
 * It keeps nothing of one change for the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TrustChanges
{
    /** @var string The metadata URL a connection whose certificates are replaced is made with. */
    public const string METADATA_URL = 'https://idp.example.com/saml/metadata.xml';

    /** @var string The provider's certificates replaced by a refresh of its metadata. */
    public const string REPLACED = 'the certificates replaced';

    /** @var string One of two trusted certificates distrusted. */
    public const string DISTRUSTED = 'a certificate distrusted';

    /** @var string A metadata signing anchor trusted. */
    public const string ANCHORED = 'an anchor trusted';

    /** @var string The connection disabled, then enabled again. */
    public const string REENABLED = 'disabled then enabled';

    /** @var list<string> Every change, by its name. */
    public const array ALL = [self::REPLACED, self::DISTRUSTED, self::ANCHORED, self::REENABLED];

    /**
     * Constructor.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Testing\FakeFetcher  $fetcher
     */
    public function __construct(

        /** The tenant the connection belongs to. */
        private string $tenantId,

        /** The connection whose trust changes. */
        private string $connectionId,

        /** What answers the refresh's fetch of the metadata. */
        private FakeFetcher $fetcher,
    ) {}

    /**
     * Make the change named to the connection that trusts the provider, and
     * answer the provider the connection trusts afterwards.
     *
     * @param  string  $change
     * @param  \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $idp
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     *
     * @throws \InvalidArgumentException
     */
    public function make(string $change, FakeSamlIdentityProvider $idp): FakeSamlIdentityProvider
    {
        return match ($change) {
            self::REPLACED   => $this->replaced($idp),
            self::DISTRUSTED => $this->distrusted($idp),
            self::ANCHORED   => $this->anchored($idp),
            self::REENABLED  => $this->reenabled($idp),
            default          => throw new \InvalidArgumentException("No trust change is named [{$change}]."),
        };
    }

    /**
     * Trust another provider certificate besides the provider's, which is
     * additive, and answer the provider that signs with it.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $idp
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    public function added(FakeSamlIdentityProvider $idp): FakeSamlIdentityProvider
    {
        $another = new FakeSamlIdentityProvider($idp->entityId);

        Assert::assertTrue(app(KeyService::class)->trustCertificate($this->tenantId, $this->connectionId, $another->certificate(), Clients::browser())->isSucceeded());

        return $another;
    }

    /**
     * Refresh the connection's metadata, which now names only a rotated
     * certificate, so the provider's is replaced.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $idp
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     *
     * @throws \Throwable
     */
    private function replaced(FakeSamlIdentityProvider $idp): FakeSamlIdentityProvider
    {
        $rotated = new FakeSamlIdentityProvider($idp->entityId);

        $this->fetcher->respond(self::METADATA_URL, FetchResult::fetched(200, [], $rotated->metadata()->toXml()));

        $refreshed = app(MetadataRefresher::class)->refreshNow(
            $this->tenantId,
            $this->connectionId,
            new Caller(new IdentityReference('App\Models\User', 'admin-1')),
            Clients::browser(),
        );

        Assert::assertSame(RefreshOutcome::REFRESHED, $refreshed->outcome);

        return $rotated;
    }

    /**
     * Trust another certificate, then distrust the provider's, so the
     * connection stays usable through the other.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $idp
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private function distrusted(FakeSamlIdentityProvider $idp): FakeSamlIdentityProvider
    {
        $keys    = app(KeyService::class);
        $another = $this->added($idp);
        $prints  = [];

        foreach ($keys->keys($this->tenantId, $this->connectionId) ?? [] as $key) {
            $prints[$key->id] = $key->key->fingerprint;
        }

        $keyId = array_search(openssl_x509_fingerprint($idp->certificate(), 'sha256'), $prints, true);

        Assert::assertIsString($keyId);
        Assert::assertTrue($keys->distrustCertificate($this->tenantId, $this->connectionId, $keyId, Clients::browser())->isSucceeded());

        return $another;
    }

    /**
     * Trust a metadata signing anchor.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $idp
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private function anchored(FakeSamlIdentityProvider $idp): FakeSamlIdentityProvider
    {
        $anchor = FakeSamlIdentityProvider::keyPair('metadata.example.com')[1];

        Assert::assertTrue(
            app(KeyService::class)->trustCertificate($this->tenantId, $this->connectionId, $anchor, Clients::browser(), use: KeyUse::METADATA_SIGNING)->isSucceeded(),
        );

        return $idp;
    }

    /**
     * Disable the connection, then enable it again.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider  $idp
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private function reenabled(FakeSamlIdentityProvider $idp): FakeSamlIdentityProvider
    {
        Assert::assertTrue(app(ConnectionLifecycle::class)->disable($this->tenantId, $this->connectionId, Clients::browser())->isSucceeded());
        Assert::assertTrue(app(ConnectionService::class)->enable($this->tenantId, $this->connectionId, Clients::browser())->isSucceeded());

        return $idp;
    }
}
