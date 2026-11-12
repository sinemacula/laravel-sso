<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;

/**
 * What an OpenID Connect connection refreshes: its discovery document from the
 * pinned issuer and its JWKS, or the saved JWKS alone when it has no document.
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
     * Whether the schedule refreshes the connection: `metadata_refresh` is on,
     * or keys fetched from a hand-saved URL would otherwise expire unattended.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    #[\Override]
    public function refreshes(Connection $connection): bool
    {
        $unattended = $connection->jwks_fetched_at !== null && self::savedKeysUri($connection) !== null;

        return (self::isSwitchedOn($connection) || $unattended) && $this->isRefreshable($connection);
    }

    /**
     * Whether the connection can be refreshed: an OIDC connection with a valid
     * issuer.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    #[\Override]
    public function isRefreshable(Connection $connection): bool
    {
        return $connection->protocol === OidcDriver::NAME && SettingRules::url($connection->settings[OidcSetting::ISSUER->value] ?? null, false) === null;
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
     * Fetch the issuer's discovery document and the JWKS it names, or only the
     * saved JWKS for a connection that fetches no document.
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

        $saved = self::savedKeysUri($connection);

        return $saved !== null && !self::isSwitchedOn($connection) ? $this->importer->fetchKeys($saved, $allowed) : $this->discovered($issuer, $saved, $allowed);
    }

    /**
     * Write what was fetched, or record the failure, unless the claim was lost
     * or the connection's settings or keys changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \SineMacula\Laravel\Sso\Metadata\FetchedMetadata  $fetched
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    #[\Override]
    public function write(RefreshClaim $claim, FetchedMetadata $fetched, ?Caller $caller, ClientContext $client): RefreshResult
    {
        return $this->writer->locked($claim, self::trustedOf(...), function (Connection $locked) use ($fetched, $caller, $client): RefreshResult {

            $metadata = $fetched->document();

            if ($metadata instanceof ProviderKeySet && $fetched->validatedAt !== null) {
                return $this->writtenKeys($locked, $metadata, $fetched->validatedAt, $caller, $client);
            }

            if (!$metadata instanceof OidcMetadata || $fetched->validatedAt === null) {
                return $this->writer->failed($locked, $fetched->reason ?? FailureReason::DISCOVERY_INVALID, $caller, $client);
            }

            $refusal = $this->refusal($locked, $metadata, $fetched->validatedAt);

            return $refusal === null ? $this->written($locked, $metadata, $fetched->validatedAt, $caller, $client) : $this->writer->failed($locked, $refusal, $caller, $client);
        }, $caller, $client);
    }

    /**
     * The discovery document and its JWKS, falling back to the saved JWKS URL;
     * never past `issuer_mismatch`, which an administrator must look at.
     *
     * @param  string  $issuer
     * @param  ?string  $saved
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return \SineMacula\Laravel\Sso\Metadata\FetchedMetadata
     *
     * @throws \InvalidArgumentException
     */
    private function discovered(string $issuer, ?string $saved, AlgorithmAllowList $allowed): FetchedMetadata
    {
        $fetched = $this->importer->fetch($issuer, $allowed);

        if ($fetched->isRead() || $saved === null || $fetched->reason === FailureReason::ISSUER_MISMATCH) {
            return $fetched;
        }

        $keys = $this->importer->fetchKeys($saved, $allowed);

        return $keys->isRead() ? $keys : $fetched;
    }

    /**
     * The connection's own allow-list, or `null`, logged by the exception's
     * class alone, so a run goes on to the next connection.
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
     * `null` when it may.
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
     * Write the settings the document moved and the keys, voiding what is in
     * flight for anything but an addition.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\OidcMetadata  $metadata
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function written(Connection $locked, OidcMetadata $metadata, CarbonImmutable $validatedAt, ?Caller $caller, ClientContext $client): RefreshResult
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

        $this->administration->connectionUpdated($locked, $names, $caller, $client);

        $this->writer->succeeded($locked, [
            'settings'        => array_replace($locked->settings, $settings),
            'jwks'            => $keys->toStored(),
            'jwks_version'    => $locked->jwks_version + 1,
            'jwks_fetched_at' => $metadata->keysValidatedAt,
        ], $validatedAt);

        return $this->writer->refreshed($locked, [...$names, ...($moved ? [self::KEYS] : [])], $trust, $caller, $client);
    }

    /**
     * Replace the keys from the saved JWKS alone, unless past their stale
     * limit, leaving the endpoints and the document's stamp untouched.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet  $keys
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function writtenKeys(Connection $locked, ProviderKeySet $keys, CarbonImmutable $validatedAt, ?Caller $caller, ClientContext $client): RefreshResult
    {
        if ($this->expiry->hasExpired(null, $validatedAt)) {
            return $this->writer->failed($locked, FailureReason::METADATA_EXPIRED, $caller, $client);
        }

        $changes = $keys->changesFrom(ProviderKeySet::fromStored($locked->jwks, OidcOptions::of($locked)->algorithms()));
        $removed = $changes['removed'] > 0;

        if ($removed) {
            $this->voider->voidFor($locked);
        }

        $this->writer->keysSucceeded($locked, [
            'jwks'            => $keys->toStored(),
            'jwks_version'    => $locked->jwks_version + 1,
            'jwks_fetched_at' => $validatedAt,
        ]);

        return $this->writer->refreshed($locked, $changes['added'] > 0 || $removed ? [self::KEYS] : [], $removed, $caller, $client);
    }

    /**
     * The snapshot of the connection's trust: its JWKS version and the settings
     * a refresh depends on, in a fixed order.
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
     * Whether the connection's `metadata_refresh` setting is on.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    private static function isSwitchedOn(Connection $connection): bool
    {
        return ($connection->settings[OidcSetting::METADATA_REFRESH->value] ?? null) === true;
    }

    /**
     * The saved `jwks_uri` of a connection no document was ever validated for,
     * when it is a URL the package may fetch; `null` otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?string
     */
    private static function savedKeysUri(Connection $connection): ?string
    {
        $uri = $connection->settings[OidcSetting::JWKS_URI->value] ?? null;

        return $connection->metadata_fetched_at === null && is_string($uri) && SettingRules::url($uri, false) === null ? $uri : null;
    }

    /**
     * Whether the document gives a UserInfo endpoint while the connection
     * fetches UserInfo; `DiscoveryDocument` has already judged the endpoints.
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
     * The settings the document moves: an endpoint that differs, and
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
