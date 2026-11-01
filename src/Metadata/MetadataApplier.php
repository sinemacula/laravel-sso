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
 * `apply()` compares and sets: the connection must still be there with the
 * metadata version and the trust version the refresh read before it fetched,
 * and the metadata signing anchors (read again with a locking read) must be the
 * ones it verified the metadata with. Anything else is `conflict`
 * (`metadata_conflict`): a change of the connection's trust, its anchors, or
 * another refresh won meanwhile, and the refresh writes nothing; the connection
 * as the winner left it is what the failure event reports. Then:
 *
 * - metadata of another entity than the pinned `idp_entity_id`, or whose
 *   endpoint would not be a valid setting, is refused `metadata_invalid`, and
 *   metadata whose `validUntil` has passed by the clock read at commit is
 *   refused `metadata_expired`;
 * - the identity provider signing certificates are replaced exactly
 *   (`Keys\KeyService::replaceTrustedCertificatesLocked()`): one no longer
 *   published is distrusted, one newly published trusted, and a removal voids
 *   what is in flight through the connection and raises its trust version;
 * - a changed single sign-on URL or binding is written to the settings and is a
 *   trust change: it voids what is in flight and raises the trust version, once
 *   with any removal, and is reported as `ConnectionUpdated`. Nothing else a
 *   connection holds (its entity id, subject settings, mapping or
 *   enforcement) is ever written;
 * - the metadata version is raised, the fetch and the `validUntil` recorded,
 *   the failures reset, the claim released, and the next refresh due after the
 *   refresh interval, never after the `validUntil`; `MetadataRefreshed` names
 *   the settings changed, in the order the connection's settings name them,
 *   then `idp_signing_certificates` when the certificates changed.
 *
 * Adding a certificate alone voids nothing and leaves the trust version as it
 * was. The identity provider's encryption certificates are never written: the
 * package encrypts nothing to an identity provider, so there is nothing to keep
 * them for.
 *
 * `fail()`, and a refusal above, record a failure: under the same lock, while
 * no other refresh has written, the failures in a row are raised, the next
 * refresh is due after the backoff for that many, the claim is released and the
 * last good settings are kept; `MetadataRefreshFailed` reports it. Every event
 * is dispatched after the transaction commits (SSO-10.5). A database error
 * propagates (SSO-11.4). It holds the key helpers, the voider, the reporters,
 * the settings and the clock, none of which keeps anything of one refresh for
 * the next (SSO-11.2).
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
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
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

        /** The clock every time is read from. */
        private Clock $clock,
    ) {}

    /**
     * Apply the metadata to the connection as it was read before the fetch,
     * unless the connection, its trust or its anchors changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $claimed
     * @param  list<string>  $anchors
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function apply(Connection $claimed, array $anchors, IdpMetadata $metadata, ?ActingIdentity $actor = null): RefreshResult
    {
        return $this->transaction(function () use ($claimed, $anchors, $metadata, $actor): RefreshResult {

            $locked = self::locked($claimed);

            if ($locked === null || !self::isUnchanged($locked, $claimed, $anchors)) {
                return $this->conflict($claimed, $locked, $actor);
            }

            $refusal = $this->refusal($locked, $metadata);

            return $refusal === null ? $this->written($locked, $metadata, $actor) : $this->failure($locked, $refusal, $actor);
        });
    }

    /**
     * Record a failed refresh of the connection as it was read before the
     * fetch, unless another refresh has written since.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $claimed
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function fail(Connection $claimed, FailureReason $reason, ?ActingIdentity $actor = null): RefreshResult
    {
        return $this->transaction(function () use ($claimed, $reason, $actor): RefreshResult {

            $locked = self::locked($claimed);

            if ($locked === null || $locked->metadata_version !== $claimed->metadata_version) {
                return $this->conflict($claimed, $locked, $actor);
            }

            return $this->failure($locked, $reason, $actor);
        });
    }

    /**
     * Why the metadata may not be applied to the locked connection, or `null`
     * when it may: another entity, an endpoint that is not a valid setting, or
     * a `validUntil` passed by now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function refusal(Connection $locked, IdpMetadata $metadata): ?FailureReason
    {
        $pinned     = $locked->settings[Saml2Setting::IDP_ENTITY_ID->value] ?? null;
        $validUntil = $metadata->validUntil();
        $merged     = [...$locked->settings, ...self::endpointsOf($metadata)];
        $violations = array_filter(
            Saml2Settings::fromArray($merged)->violations(),
            static fn (SettingViolation $violation): bool => in_array($violation->setting, self::ENDPOINTS, true),
        );

        $invalid = $metadata->entityId() !== $pinned || $violations !== [];
        $expired = $validUntil           !== null && $validUntil <= $this->clock->now();

        return match (true) {
            $invalid => FailureReason::METADATA_INVALID,
            $expired => FailureReason::METADATA_EXPIRED,
            default  => null,
        };
    }

    /**
     * Replace the certificates, write the endpoints and the refresh, and report
     * them; a certificate refused records a failure instead, with nothing
     * replaced.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function written(Connection $locked, IdpMetadata $metadata, ?ActingIdentity $actor): RefreshResult
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
            'metadata_fetched_at'       => $now,
            'metadata_valid_until'      => $validUntil,
            'metadata_refresh_at'       => $this->nextRefreshAt($now, $validUntil),
            'metadata_refresh_failures' => 0,
            'metadata_claimed_until'    => null,
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
     * row, the next refresh after the backoff, the claim released.
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
        ])->save();

        $this->events->refreshFailed($locked, $reason, $failures, $next, $actor);

        return RefreshResult::failed($locked->id, $reason, $failures, $next);
    }

    /**
     * The refresh lost to a change made while it fetched, and writes nothing;
     * the failure is reported with the connection as the winner left it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $claimed
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     */
    private function conflict(Connection $claimed, ?Connection $locked, ?ActingIdentity $actor): RefreshResult
    {
        if ($locked !== null) {
            $this->events->refreshFailed($locked, FailureReason::METADATA_CONFLICT, $locked->metadata_refresh_failures, $locked->metadata_refresh_at, $actor);
        }

        return RefreshResult::conflict($claimed->id);
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
     * Whether the locked connection is still the one the refresh read before it
     * fetched: the same metadata and trust versions, and the same anchors.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $claimed
     * @param  list<string>  $anchors
     * @return bool
     */
    private static function isUnchanged(Connection $locked, Connection $claimed, array $anchors): bool
    {
        $versions = $locked->metadata_version === $claimed->metadata_version && $locked->trust_version === $claimed->trust_version;

        return $versions && self::anchorsOf($locked) === self::sorted($anchors);
    }

    /**
     * The fingerprints of the locked connection's metadata signing anchors,
     * read with a locking read, sorted.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return list<string>
     */
    private static function anchorsOf(Connection $locked): array
    {
        $fingerprints = ConnectionKey::query()->useWritePdo()
            ->where('connection_id', $locked->id)
            ->where('use', KeyUse::METADATA_SIGNING->value)
            ->lockForUpdate()
            ->toBase()
            ->pluck('fingerprint')
            ->all();

        return self::sorted(array_map(strval(...), $fingerprints));
    }

    /**
     * The strings, sorted.
     *
     * @param  list<string>  $values
     * @return list<string>
     */
    private static function sorted(array $values): array
    {
        sort($values);

        return $values;
    }

    /**
     * The connection read again, locked for update until the transaction ends,
     * or `null` when it is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $claimed
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private static function locked(Connection $claimed): ?Connection
    {
        $found = Connection::query()->useWritePdo()->whereKey($claimed->id)->lockForUpdate()->first();

        return $found?->id === $claimed->id ? $found : null;
    }
}
