<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Administration\MetadataEvents;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;

/**
 * Writes what a metadata refresh found (SSO-2.8, SSO-2.13), each write in one
 * transaction on the storage connection that locks the connection's row first,
 * the only lock a refresh takes, and decides from what that locking read gives.
 *
 * `apply()` and `fail()` each compare and set against the refresh's claim
 * (`RefreshClaim`): the connection must still be there, still hold the claim's
 * token (no other server took the claim over once it expired), and have the
 * metadata version and the trust version the refresh read before it claimed;
 * and its identity provider signing certificates and metadata signing anchors,
 * read again with a locking read, must be exactly the claim's. Anything else is
 * `conflict` (`metadata_conflict`): a change of the connection's trust, a
 * certificate or anchor added or removed (additive or not), another refresh won
 * meanwhile, or the claim lost, and the refresh writes nothing; the connection
 * as the winner left it is what the failure event reports. Then, for `apply()`:
 *
 * - metadata of another entity than the pinned `idp_entity_id`, or whose
 *   endpoint would not be a valid setting, is refused `metadata_invalid`, and
 *   metadata that has expired by the clock read at commit is refused
 *   `metadata_expired`: its expiry is the earlier of its `validUntil` (an
 *   enclosing aggregate's included) and the moment it was validated plus the
 *   stale limit (`MetadataExpiry::hasExpired()`);
 * - the identity provider signing certificates are replaced exactly
 *   (`Keys\KeyService::replaceTrustedCertificatesLocked()`): one no longer
 *   published is distrusted, one newly published trusted, and a removal voids
 *   what is in flight through the connection and raises its trust version;
 * - a changed single sign-on URL or binding is written to the settings and is a
 *   trust change: it voids what is in flight and raises the trust version, once
 *   with any removal, and is reported as `ConnectionUpdated`. Nothing else a
 *   connection holds (its entity id, subject settings, mapping or
 *   enforcement) is ever written;
 * - the metadata version is raised, `metadata_fetched_at` set to the moment the
 *   fetched document was validated (never the later moment it commits),
 *   `metadata_valid_until` to its `validUntil`, the failures reset, the claim
 *   and its token released, and the next refresh due after the refresh
 *   interval, never after the `validUntil`; `MetadataRefreshed` names the
 *   settings changed, in the order the connection's settings name them, then
 *   `idp_signing_certificates` when the certificates changed.
 *
 * Adding a certificate alone voids nothing and leaves the trust version as it
 * was. The identity provider's encryption certificates are never written: the
 * package encrypts nothing to an identity provider, so there is nothing to keep
 * them for.
 *
 * `fail()`, and a refusal above, record a failure: under the same lock and the
 * same comparison, the failures in a row are raised, the next refresh is due
 * after the backoff for that many, the claim and its token are released and the
 * last good settings are kept; `MetadataRefreshFailed` reports it. Every event
 * is dispatched after the transaction commits (SSO-10.5). A database error
 * propagates (SSO-11.4). It holds the key helpers, the voider, the reporters,
 * the settings, the expiry and the clock, none of which keeps anything of one
 * refresh for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MetadataApplier
{
    /** @var string The name a change of the trusted signing certificates is reported under. */
    public const string SIGNING_CERTIFICATES = 'idp_signing_certificates';

    /** @var list<string> The settings a refresh may write. */
    public const array ENDPOINTS = ['sso_url', 'sso_binding'];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyService  $keys
     * @param  \SineMacula\Laravel\Sso\Connections\InFlightVoider  $voider
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $administration
     * @param  \SineMacula\Laravel\Sso\Administration\MetadataEvents  $events
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataExpiry  $expiry
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** Replaces the trusted certificates under the lock. */
        private KeyService $keys,

        /** Voids what an endpoint change leaves in flight. */
        private InFlightVoider $voider,

        /** Reports an endpoint change. */
        private AdministrationEvents $administration,

        /** Reports the refresh or its failure. */
        private MetadataEvents $events,

        /** The refresh interval and the backoff. */
        private MetadataSettings $settings,

        /** Whether the metadata has expired by the commit. */
        private MetadataExpiry $expiry,

        /** The clock every time is read from. */
        private Clock $clock,
    ) {}

    /**
     * Apply the metadata, validated at the moment given, to the connection the
     * claim holds, unless the claim was lost or the connection, its trust or
     * its certificates changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function apply(RefreshClaim $claim, IdpMetadata $metadata, CarbonImmutable $validatedAt, ?ActingIdentity $actor = null): RefreshResult
    {
        return $this->transaction(function () use ($claim, $metadata, $validatedAt, $actor): RefreshResult {

            $locked = self::locked($claim);

            if ($locked === null || !self::isUnchanged($locked, $claim)) {
                return $this->conflict($claim, $locked, $actor);
            }

            $refusal = $this->refusal($locked, $metadata, $validatedAt);

            return $refusal === null ? $this->written($locked, $metadata, $validatedAt, $actor) : $this->failure($locked, $refusal, $actor);
        });
    }

    /**
     * Record a failed refresh of the connection the claim holds, unless the
     * claim was lost or the connection, its trust or its certificates changed
     * meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function fail(RefreshClaim $claim, FailureReason $reason, ?ActingIdentity $actor = null): RefreshResult
    {
        return $this->transaction(function () use ($claim, $reason, $actor): RefreshResult {

            $locked = self::locked($claim);

            if ($locked === null || !self::isUnchanged($locked, $claim)) {
                return $this->conflict($claim, $locked, $actor);
            }

            return $this->failure($locked, $reason, $actor);
        });
    }

    /**
     * Why the metadata may not be applied to the locked connection, or `null`
     * when it may: another entity, an endpoint that is not a valid setting, or
     * metadata validated at the moment given that has expired by now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function refusal(Connection $locked, IdpMetadata $metadata, CarbonImmutable $validatedAt): ?FailureReason
    {
        $pinned     = $locked->settings[Saml2Setting::IDP_ENTITY_ID->value] ?? null;
        $merged     = [...$locked->settings, ...self::endpointsOf($metadata)];
        $violations = array_filter(
            Saml2Settings::fromArray($merged)->violations(),
            static fn (SettingViolation $violation): bool => in_array($violation->setting, self::ENDPOINTS, true),
        );

        $invalid = $metadata->entityId() !== $pinned || $violations !== [];

        return match (true) {
            $invalid                                                         => FailureReason::METADATA_INVALID,
            $this->expiry->hasExpired($metadata->validUntil(), $validatedAt) => FailureReason::METADATA_EXPIRED,
            default                                                          => null,
        };
    }

    /**
     * Replace the certificates, write the endpoints and the refresh, and report
     * them; a certificate refused records a failure instead, with nothing
     * replaced.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function written(Connection $locked, IdpMetadata $metadata, CarbonImmutable $validatedAt, ?ActingIdentity $actor): RefreshResult
    {
        $changes = $this->keys->replaceTrustedCertificatesLocked($locked, array_column($metadata->signingCertificates(), 'certificate'), $actor);

        if ($changes['violations'] !== []) {
            return $this->failure($locked, FailureReason::METADATA_INVALID, $actor);
        }

        $removed   = $changes['retired'] !== [];
        $stored    = $locked->settings;
        $endpoints = array_filter(self::endpointsOf($metadata), static fn (string $value, string $name): bool => ($stored[$name] ?? null) !== $value, ARRAY_FILTER_USE_BOTH);

        if ($endpoints !== [] && !$removed) {
            $this->voider->voidFor($locked);
        }

        $now        = $this->clock->now();
        $validUntil = $metadata->validUntil();

        $locked->forceFill([
            'settings'                  => array_replace($locked->settings, $endpoints),
            'metadata_version'          => $locked->metadata_version + 1,
            'metadata_fetched_at'       => $validatedAt,
            'metadata_valid_until'      => $validUntil,
            'metadata_refresh_at'       => $this->nextRefreshAt($now, $validUntil),
            'metadata_refresh_failures' => 0,
            'metadata_claimed_until'    => null,
            'metadata_claim_token'      => null,
        ])->save();

        $certificates = $changes['added'] !== [] || $removed;
        $changed      = [...array_keys($endpoints), ...($certificates ? [self::SIGNING_CERTIFICATES] : [])];
        $trustChanged = $removed || $endpoints !== [];

        $this->administration->connectionUpdated($locked, array_keys($endpoints), $actor);
        $this->events->refreshed($locked, $changed, $locked->metadata_version, $trustChanged, $actor);

        return RefreshResult::refreshed($locked->id, $changed, $locked->metadata_version, $trustChanged);
    }

    /**
     * Record a failed refresh of the locked connection: one more failure in a
     * row, the next refresh after the backoff, the claim and its token
     * released.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     */
    private function failure(Connection $locked, FailureReason $reason, ?ActingIdentity $actor): RefreshResult
    {
        $failures = $locked->metadata_refresh_failures + 1;
        $next     = $this->clock->now()->addSeconds($this->settings->backoffSeconds($failures));

        $locked->forceFill([
            'metadata_refresh_failures' => $failures,
            'metadata_refresh_at'       => $next,
            'metadata_claimed_until'    => null,
            'metadata_claim_token'      => null,
        ])->save();

        $this->events->refreshFailed($locked, $reason, $failures, $next, $actor);

        return RefreshResult::failed($locked->id, $reason, $failures, $next);
    }

    /**
     * The refresh lost its claim or to a change made while it fetched, and
     * writes nothing; the failure is reported with the connection as the winner
     * left it.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     */
    private function conflict(RefreshClaim $claim, ?Connection $locked, ?ActingIdentity $actor): RefreshResult
    {
        if ($locked !== null) {
            $this->events->refreshFailed($locked, FailureReason::METADATA_CONFLICT, $locked->metadata_refresh_failures, $locked->metadata_refresh_at, $actor);
        }

        return RefreshResult::conflict($claim->connection->id);
    }

    /**
     * When the next refresh is due after one that succeeded now: after the
     * refresh interval, or at the `validUntil` when that comes first.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\Carbon\CarbonImmutable  $validUntil
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private function nextRefreshAt(CarbonImmutable $now, ?CarbonImmutable $validUntil): CarbonImmutable
    {
        $next = $now->addSeconds($this->settings->refreshIntervalSeconds());

        return $validUntil === null ? $next : $next->min($validUntil);
    }

    /**
     * Run the work in one transaction on the storage connection.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Metadata\RefreshResult  $work
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    private function transaction(\Closure $work): RefreshResult
    {
        return DB::connection(StorageConnection::name())->transaction($work);
    }

    /**
     * The settings the metadata gives a connection's endpoint, in the order the
     * connection's settings name them.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @return array<string, string>
     *
     * @throws \LogicException
     */
    private static function endpointsOf(IdpMetadata $metadata): array
    {
        return [Saml2Setting::SSO_URL->value => $metadata->ssoUrl(), Saml2Setting::SSO_BINDING->value => $metadata->ssoBinding()];
    }

    /**
     * Whether the locked connection is still the one the refresh claimed: the
     * claim's token, the same metadata and trust versions, and exactly the same
     * trusted certificates and anchors.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return bool
     */
    private static function isUnchanged(Connection $locked, RefreshClaim $claim): bool
    {
        $claimed  = $claim->connection;
        $owned    = $locked->metadata_claim_token === $claim->token;
        $versions = $locked->metadata_version     === $claimed->metadata_version && $locked->trust_version === $claimed->trust_version;

        return $owned && $versions && self::trustedOf($locked) === $claim->trusted;
    }

    /**
     * The sorted fingerprints of the locked connection's identity provider
     * signing certificates and metadata signing anchors, by use, read with a
     * locking read.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return array<string, list<string>>
     */
    private static function trustedOf(Connection $locked): array
    {
        $rows = ConnectionKey::query()->useWritePdo()
            ->where('connection_id', $locked->id)
            ->whereIn('use', [KeyUse::IDP_SIGNING->value, KeyUse::METADATA_SIGNING->value])
            ->lockForUpdate()
            ->toBase()
            ->get(['use', 'fingerprint']);

        $trusted = [KeyUse::IDP_SIGNING->value => [], KeyUse::METADATA_SIGNING->value => []];

        foreach ($rows as $row) {
            $trusted[(string) $row->use][] = (string) $row->fingerprint;
        }

        return array_map(static function (array $fingerprints): array {
            sort($fingerprints);

            return $fingerprints;
        }, $trusted);
    }

    /**
     * The connection the claim holds read again, locked for update until the
     * transaction ends, or `null` when it is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private static function locked(RefreshClaim $claim): ?Connection
    {
        $id    = $claim->connection->id;
        $found = Connection::query()->useWritePdo()->whereKey($id)->lockForUpdate()->first();

        return $found?->id === $id ? $found : null;
    }
}
