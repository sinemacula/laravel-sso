<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;

/**
 * Writes what a SAML metadata refresh found (SSO-2.8, SSO-2.13), through the
 * shared `RefreshWriter`: each write in one transaction on the storage
 * connection that locks the connection's row first, the only lock a refresh
 * takes, and decides from what that locking read gives.
 *
 * `apply()` and `fail()` each compare and set against the refresh's claim
 * (`RefreshClaim`, `RefreshWriter::locked()`): the connection must still be
 * there, still hold the claim's token, and have the metadata version and the
 * trust version the refresh read before it claimed; and its identity provider
 * signing certificates and metadata signing anchors, read again with a locking
 * read (`trustedOf()`), must be exactly the claim's. Anything else is
 * `conflict` (`metadata_conflict`): a change of the connection's trust, a
 * certificate or anchor added or removed (additive or not), another refresh won
 * meanwhile, or the claim lost, and the refresh writes nothing. Then, for
 * `apply()`:
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
 * - the refresh's bookkeeping is written with the endpoints
 *   (`RefreshWriter::succeeded()`), and `MetadataRefreshed` names the settings
 *   changed, in the order the connection's settings name them, then
 *   `idp_signing_certificates` when the certificates changed.
 *
 * Adding a certificate alone voids nothing and leaves the trust version as it
 * was. The identity provider's encryption certificates are never written: the
 * package encrypts nothing to an identity provider, so there is nothing to keep
 * them for.
 *
 * `fail()`, and a refusal above, record a failure (`RefreshWriter::failed()`).
 * Every event is dispatched after the transaction commits (SSO-10.5). A
 * database error propagates (SSO-11.4). It holds the key helpers, the voider,
 * the reporter, the expiry and the writer, none of which keeps anything of one
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
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataExpiry  $expiry
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshWriter  $writer
     */
    public function __construct(

        /** Replaces the trusted certificates under the lock. */
        private KeyService $keys,

        /** Voids what an endpoint change leaves in flight. */
        private InFlightVoider $voider,

        /** Reports an endpoint change. */
        private AdministrationEvents $administration,

        /** Whether the metadata has expired by the commit. */
        private MetadataExpiry $expiry,

        /** Locks, compares and sets, and records the refresh or its failure. */
        private RefreshWriter $writer,
    ) {}

    /**
     * Apply the metadata, validated at the moment given, to the connection the
     * claim holds, unless the claim was lost or the connection, its trust or
     * its certificates changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function apply(RefreshClaim $claim, IdpMetadata $metadata, CarbonImmutable $validatedAt, ClientContext $client, ?ActingIdentity $actor = null): RefreshResult
    {
        return $this->writer->locked($claim, self::trustedOf(...), function (Connection $locked) use ($metadata, $validatedAt, $actor, $client): RefreshResult {

            $refusal = $this->refusal($locked, $metadata, $validatedAt);

            return $refusal === null ? $this->written($locked, $metadata, $validatedAt, $actor, $client) : $this->writer->failed($locked, $refusal, $actor, $client);
        }, $actor, $client);
    }

    /**
     * Record a failed refresh of the connection the claim holds, unless the
     * claim was lost or the connection, its trust or its certificates changed
     * meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function fail(RefreshClaim $claim, FailureReason $reason, ClientContext $client, ?ActingIdentity $actor = null): RefreshResult
    {
        return $this->writer->locked(
            $claim,
            self::trustedOf(...),
            fn (Connection $locked): RefreshResult => $this->writer->failed($locked, $reason, $actor, $client),
            $actor,
            $client,
        );
    }

    /**
     * The sorted fingerprints of the connection's identity provider signing
     * certificates and metadata signing anchors, by use, read with a locking
     * read: the snapshot a SAML refresh compares under the lock.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return array<string, list<string>>
     */
    public static function trustedOf(Connection $locked): array
    {
        $rows = ConnectionKey::query()->useWritePdo()
            ->where('connection_id', $locked->id)
            ->whereIn('use', [KeyUse::IDP_SIGNING->value, KeyUse::METADATA_SIGNING->value])
            ->orderBy('fingerprint')
            ->lockForUpdate()
            ->toBase()
            ->get(['use', 'fingerprint']);

        $trusted = [KeyUse::IDP_SIGNING->value => [], KeyUse::METADATA_SIGNING->value => []];

        foreach ($rows as $row) {
            $trusted[(string) $row->use][] = (string) $row->fingerprint;
        }

        return $trusted;
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
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function written(Connection $locked, IdpMetadata $metadata, CarbonImmutable $validatedAt, ?ActingIdentity $actor, ClientContext $client): RefreshResult
    {
        $changes = $this->keys->replaceTrustedCertificatesLocked($locked, array_column($metadata->signingCertificates(), 'certificate'), $client, $actor);

        if ($changes['violations'] !== []) {
            return $this->writer->failed($locked, FailureReason::METADATA_INVALID, $actor, $client);
        }

        $removed   = $changes['retired'] !== [];
        $stored    = $locked->settings;
        $endpoints = array_filter(self::endpointsOf($metadata), static fn (string $value, string $name): bool => ($stored[$name] ?? null) !== $value, ARRAY_FILTER_USE_BOTH);

        if ($endpoints !== [] && !$removed) {
            $this->voider->voidFor($locked);
        }

        $this->writer->succeeded($locked, ['settings' => array_replace($locked->settings, $endpoints)], $validatedAt, $metadata->validUntil());

        $certificates = $changes['added'] !== [] || $removed;
        $changed      = [...array_keys($endpoints), ...($certificates ? [self::SIGNING_CERTIFICATES] : [])];

        $this->administration->connectionUpdated($locked, array_keys($endpoints), $actor, $client);

        return $this->writer->refreshed($locked, $changed, $removed || $endpoints !== [], $actor, $client);
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
}
