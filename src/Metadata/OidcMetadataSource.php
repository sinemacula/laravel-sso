<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;

/**
 * What an OpenID Connect connection refreshes on the schedule and when an
 * administrator asks (SSO-2.8, SSO-7.3, SSO-11.12): its discovery document,
 * from its pinned issuer, and its JWKS, through the shared refresh machinery
 * (`MetadataSource`).
 *
 * - It refreshes while its `metadata_refresh` setting is on and its `issuer` is
 *   a valid issuer: the only URL derived is the issuer's discovery document.
 * - Its snapshot is its JWKS version and the settings a refresh depends on or
 *   may change, in a fixed order; it is read again from the locked row.
 * - It fetches as an import does (`DiscoveryImporter::fetch()`), pinned to the
 *   saved issuer, so a document naming another is `issuer_mismatch`, a refresh
 *   never changing the issuer, then the JWKS at the document's `jwks_uri`, read
 *   under the connection's own allow-list. An allow-list that cannot be built
 *   from what is stored is contained: the refresh is `settings_invalid`, and
 *   the exception is logged by its class alone, so a run goes on to the next
 *   connection.
 * - It writes through `RefreshWriter`. Under the lock, a document with an
 *   endpoint that would not be a valid setting, or with no `userinfo_endpoint`
 *   while `fetch_userinfo` is on, is `discovery_invalid`, and a document or
 *   JWKS whose stale limit has passed by commit
 *   (`MetadataExpiry::hasExpired()`, each from its own validated moment) is
 *   `metadata_expired`; each records a failure and keeps the last good settings
 *   and keys.
 * - It may change only `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
 *   `userinfo_endpoint` (set or changed, never removed) and `returns_iss`
 *   (false to true only), and replaces the JWKS exactly, never as a union.
 *   Nothing else a connection holds (its issuer, client id or authentication,
 *   secret, scopes, algorithms, mapping, subject meaning or enforcement) is
 *   ever written.
 * - A change of a setting, or a key removed or replaced under the same `kid`,
 *   voids what is in flight through the connection and raises its trust version
 *   once (`Connections\InFlightVoider::voidFor()`); a key added alone voids
 *   nothing and leaves it as it was. A changed setting is reported
 *   `ConnectionUpdated`, then `MetadataRefreshed` names them, in the order
 *   `OidcSetting` names them, then `jwks` when the keys changed.
 *
 * Every event is dispatched after the transaction commits (SSO-10.5). A
 * database error propagates (SSO-11.4). It holds the claims, the importer, the
 * writer, the voider, the reporter, the expiry and the logger, none of which
 * keeps anything of one refresh for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OidcMetadataSource extends MetadataSource
{
    /** @var string The name a change of the keys is reported under. */
    public const string KEYS = 'jwks';

    /** @var list<string> The settings a refresh depends on or may change, in the order the snapshot holds them. */
    private const array SNAPSHOT = [
        'issuer',
        'authorization_endpoint',
        'token_endpoint',
        'jwks_uri',
        'userinfo_endpoint',
        'returns_iss',
        'id_token_algorithms',
        'fetch_userinfo',
    ];

    /** @var list<string> The endpoints a refresh may set or change. */
    private const array ENDPOINTS = ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint'];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaims  $claims
     * @param  \SineMacula\Laravel\Sso\Metadata\DiscoveryImporter  $importer
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshWriter  $writer
     * @param  \SineMacula\Laravel\Sso\Connections\InFlightVoider  $voider
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $administration
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataExpiry  $expiry
     * @param  \Psr\Log\LoggerInterface  $logger
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** Claims the connection's refresh. */
        private RefreshClaims $claims,

        /** Fetches and validates the discovery document and the JWKS. */
        private DiscoveryImporter $importer,

        /** Locks, compares and sets, and records the refresh or its failure. */
        private RefreshWriter $writer,

        /** Voids what a trust change leaves in flight. */
        private InFlightVoider $voider,

        /** Reports a change of the connection's settings. */
        private AdministrationEvents $administration,

        /** Whether what was fetched has expired by the commit. */
        private MetadataExpiry $expiry,

        /** The sanitising logger a contained exception is logged to. */
        private LoggerInterface $logger,
    ) {}

    /**
     * The OIDC protocol.
     *
     * @return string
     */
    #[\Override]
    public function protocol(): string
    {
        return OidcDriver::NAME;
    }

    /**
     * Whether the connection refreshes: an OIDC connection with
     * `metadata_refresh` on and a valid issuer.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    #[\Override]
    public function refreshes(Connection $connection): bool
    {
        $switchedOn = $connection->protocol === OidcDriver::NAME && ($connection->settings[OidcSetting::METADATA_REFRESH->value] ?? null) === true;

        return $switchedOn && SettingRules::url($connection->settings[OidcSetting::ISSUER->value] ?? null, false) === null;
    }

    /**
     * Snapshot the connection's JWKS version and settings and claim its
     * refresh.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Metadata\RefreshClaim
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    #[\Override]
    public function claim(Connection $connection): ?RefreshClaim
    {
        return $this->claims->claim($connection, self::trustedOf($connection));
    }

    /**
     * Fetch the saved issuer's discovery document, then the JWKS it names under
     * the connection's own allow-list, noting each moment it validated.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return \SineMacula\Laravel\Sso\Metadata\FetchedMetadata
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function fetch(RefreshClaim $claim): FetchedMetadata
    {
        $connection = $claim->connection;
        $allowed    = $this->allowListOf($connection);
        $issuer     = $connection->settings[OidcSetting::ISSUER->value] ?? null;

        if ($allowed === null || !is_string($issuer)) {
            return FetchedMetadata::refused(FailureReason::SETTINGS_INVALID, FetchStatus::REFUSED);
        }

        return $this->importer->fetch($issuer, $allowed);
    }

    /**
     * Write what was fetched, or record the failure, under the connection's
     * lock, unless the claim was lost or the connection's settings or keys
     * changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \SineMacula\Laravel\Sso\Metadata\FetchedMetadata  $fetched
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    #[\Override]
    public function write(RefreshClaim $claim, FetchedMetadata $fetched, ?ActingIdentity $actor): RefreshResult
    {
        return $this->writer->locked($claim, self::trustedOf(...), function (Connection $locked) use ($fetched, $actor): RefreshResult {

            $metadata = $fetched->document();

            if (!$metadata instanceof OidcMetadata || $fetched->validatedAt === null) {
                return $this->writer->failed($locked, $fetched->reason ?? FailureReason::DISCOVERY_INVALID, $actor);
            }

            $refusal = $this->refusal($locked, $metadata, $fetched->validatedAt);

            return $refusal === null ? $this->written($locked, $metadata, $fetched->validatedAt, $actor) : $this->writer->failed($locked, $refusal, $actor);
        }, $actor);
    }

    /**
     * The connection's own allow-list; `null`, once its exception is logged by
     * its class alone, when what is stored cannot give one.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList
     */
    private function allowListOf(Connection $connection): ?AlgorithmAllowList
    {
        try {
            return OidcOptions::of($connection)->algorithms();
        } catch (\InvalidArgumentException $exception) {
            $this->logger->warning('sso.metadata.refresh_contained', ['exception' => $exception::class]);

            return null;
        }
    }

    /**
     * Why what was fetched may not be written to the locked connection, or
     * `null` when it may: a document that would not give valid settings, or
     * anything validated at a moment whose stale limit has passed by now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\OidcMetadata  $metadata
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     */
    private function refusal(Connection $locked, OidcMetadata $metadata, CarbonImmutable $validatedAt): ?FailureReason
    {
        $expired = $this->expiry->hasExpired(null, $validatedAt) || $this->expiry->hasExpired(null, $metadata->keysValidatedAt);

        return match (true) {
            !self::isAcceptable($locked, $metadata->document()) => FailureReason::DISCOVERY_INVALID,
            $expired                                            => FailureReason::METADATA_EXPIRED,
            default                                             => null,
        };
    }

    /**
     * Change the settings the document moved and replace the keys exactly, void
     * what is in flight when that is a trust change, write the refresh's
     * bookkeeping and report them.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\OidcMetadata  $metadata
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function written(Connection $locked, OidcMetadata $metadata, CarbonImmutable $validatedAt, ?ActingIdentity $actor): RefreshResult
    {
        $settings = self::settingChanges($locked, $metadata->document());
        $keys     = $metadata->keys();
        $changes  = $keys->changesFrom(ProviderKeySet::fromStored($locked->jwks, OidcOptions::of($locked)->algorithms()));
        $removed  = $changes['removed'] > 0;
        $added    = $changes['added']   > 0;
        $names    = array_keys($settings);
        $trust    = $names !== [] || $removed;
        $moved    = $added        || $removed;

        if ($trust) {
            $this->voider->voidFor($locked);
        }

        $this->administration->connectionUpdated($locked, $names, $actor);

        $this->writer->succeeded($locked, [
            'settings'        => array_replace($locked->settings, $settings),
            'jwks'            => $keys->toStored(),
            'jwks_version'    => $locked->jwks_version + 1,
            'jwks_fetched_at' => $metadata->keysValidatedAt,
        ], $validatedAt);

        return $this->writer->refreshed($locked, [...$names, ...($moved ? [self::KEYS] : [])], $trust, $actor);
    }

    /**
     * The snapshot of the connection's trust: its JWKS version and the settings
     * a refresh depends on or may change, in a fixed order whatever order they
     * were read in.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array{jwks_version: int, settings: array<string, mixed>}
     */
    private static function trustedOf(Connection $connection): array
    {
        $settings = [];

        foreach (self::SNAPSHOT as $name) {
            $settings[$name] = $connection->settings[$name] ?? null;
        }

        return ['jwks_version' => $connection->jwks_version, 'settings' => $settings];
    }

    /**
     * Whether the document gives what the locked connection needs: its UserInfo
     * endpoint, while the connection fetches UserInfo. Every endpoint it gives
     * has already passed the setting's own rule (`DiscoveryDocument`).
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\DiscoveryDocument  $document
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isAcceptable(Connection $locked, DiscoveryDocument $document): bool
    {
        return ($locked->settings[OidcSetting::FETCH_USERINFO->value] ?? null) !== true || array_key_exists(OidcSetting::USERINFO_ENDPOINT->value, $document->settings());
    }

    /**
     * The settings the document moves on the locked connection, in the order
     * `OidcSetting` names them: an endpoint it gives that differs, and
     * `returns_iss` from false to true, never back.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\DiscoveryDocument  $document
     * @return array<string, mixed>
     *
     * @throws \LogicException
     */
    private static function settingChanges(Connection $locked, DiscoveryDocument $document): array
    {
        $given = $document->settings();
        $names = [...self::ENDPOINTS, ...($given[OidcSetting::RETURNS_ISS->value] ? [OidcSetting::RETURNS_ISS->value] : [])];

        return array_filter(
            array_intersect_key($given, array_flip($names)),
            static fn (mixed $value, string $name): bool => ($locked->settings[$name] ?? null) !== $value,
            ARRAY_FILTER_USE_BOTH,
        );
    }
}
