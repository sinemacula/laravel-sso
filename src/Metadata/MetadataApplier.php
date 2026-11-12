<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;

/**
 * Writes what a SAML metadata refresh found through `RefreshWriter`: the
 * signing certificates and the single sign-on endpoint, nothing else.
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
     * Apply the metadata to the claimed connection, unless the claim was lost
     * or its trust changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function apply(RefreshClaim $claim, IdpMetadata $metadata, CarbonImmutable $validatedAt, ClientContext $client, ?Caller $caller = null): RefreshResult
    {
        return $this->writer->locked($claim, self::trustedOf(...), function (Connection $locked) use ($metadata, $validatedAt, $caller, $client): RefreshResult {

            $refusal = $this->refusal($locked, $metadata, $validatedAt);

            return $refusal === null ? $this->written($locked, $metadata, $validatedAt, $caller, $client) : $this->writer->failed($locked, $refusal, $caller, $client);
        }, $caller, $client);
    }

    /**
     * Record a failed refresh of the claimed connection, unless the claim was
     * lost or its trust changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function fail(RefreshClaim $claim, FailureReason $reason, ClientContext $client, ?Caller $caller = null): RefreshResult
    {
        return $this->writer->locked(
            $claim,
            self::trustedOf(...),
            fn (Connection $locked): RefreshResult => $this->writer->failed($locked, $reason, $caller, $client),
            $caller,
            $client,
        );
    }

    /**
     * The sorted fingerprints of the connection's signing certificates and
     * anchors, by use, read locked: the snapshot a SAML refresh compares.
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
     * when it may.
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
     * them; a certificate refused records a failure instead.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function written(Connection $locked, IdpMetadata $metadata, CarbonImmutable $validatedAt, ?Caller $caller, ClientContext $client): RefreshResult
    {
        $changes = $this->keys->replaceTrustedCertificatesLocked($locked, array_column($metadata->signingCertificates(), 'certificate'), $client, $caller);

        if ($changes['violations'] !== []) {
            return $this->writer->failed($locked, FailureReason::METADATA_INVALID, $caller, $client);
        }

        $removed   = $changes['retired'] !== [];
        $stored    = $locked->settings;
        $endpoints = array_filter(self::endpointsOf($metadata), static fn (string $value, string $name): bool => ($stored[$name] ?? null) !== $value, ARRAY_FILTER_USE_BOTH);

        // A removal has already voided and raised the trust version once
        if ($endpoints !== [] && !$removed) {
            $this->voider->voidFor($locked);
        }

        $this->writer->succeeded($locked, ['settings' => array_replace($locked->settings, $endpoints)], $validatedAt, $metadata->validUntil());

        $certificates = $changes['added'] !== [] || $removed;
        $changed      = [...array_keys($endpoints), ...($certificates ? [self::SIGNING_CERTIFICATES] : [])];

        $this->administration->connectionUpdated($locked, array_keys($endpoints), $caller, $client);

        return $this->writer->refreshed($locked, $changed, $removed || $endpoints !== [], $caller, $client);
    }

    /**
     * The endpoint settings the metadata gives, in the connection's order.
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
