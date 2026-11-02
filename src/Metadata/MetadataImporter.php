<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataReader;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Imports a SAML identity provider's metadata, given as XML or fetched from a
 * URL, and answers the settings it proposes (SSO-2.8, SSO-2.11), for an
 * administrator to review: an import writes and trusts nothing, and reports no
 * event. While the SAML protocol is not available (`sso.features.saml2` off),
 * every import is refused as `protocol_unavailable` before anything is looked
 * up, read or fetched. What it proposes is saved, if the administrator accepts
 * it, through `Connections\ConnectionService::update()` and
 * `Keys\KeyService::trustCertificate()`, each with its own freshness check.
 *
 * The administrator names the entity, which is chosen from aggregate metadata
 * by that id alone (`Protocols\Saml2\Library\MetadataReader`). Naming the
 * tenant's SAML connection the metadata is for (optional) holds the metadata to
 * the connection's metadata signing anchors, when it has any, so unsigned
 * metadata, or metadata no anchor signed, is refused; and prefers the binding
 * the connection uses now. A connection that is unknown, another tenant's or
 * not SAML is `connection_not_found`, exactly as an unknown one.
 *
 * `importUrl()` fetches the URL through the package's fetcher as a metadata
 * request, with no credential and every rule of the safe fetcher (SSO-2.9);
 * with a connection named, each import counts against the connection's metadata
 * limit (`sso.rate_limits.metadata`) before anything is fetched. The document,
 * fetched or given, is capped at `sso.metadata.max_bytes`, not the fetcher's
 * `max_response_bytes`: the fetch stops reading past it and a document over it
 * is never parsed. The fetch runs while `importUrl()` is called, so a large
 * aggregate is imported from the console or a queued job, never a web request,
 * whose timeout and memory it could exceed. The proposal is checked as the
 * connection's settings would be (an `https` single sign-on URL, an entity id
 * that is a URL or a URN), and refused as `metadata_invalid` otherwise.
 *
 * It holds the reader, the lookup, the key ring, the fetcher, the limiter and
 * the protocols, none of which keeps anything of one request for the next
 * (SSO-11.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MetadataImporter
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataReader  $reader
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $connections
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  \SineMacula\Laravel\Sso\Contracts\Fetcher  $fetcher
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     */
    public function __construct(

        /** Reads the metadata for the pinned entity. */
        private MetadataReader $reader,

        /** Finds the tenant's connection, on the write connection. */
        private ConnectionFinder $connections,

        /** The connection's metadata signing anchors. */
        private KeyRing $keys,

        /** Fetches a metadata URL. */
        private Fetcher $fetcher,

        /** Limits how often a connection's metadata is imported. */
        private AttemptLimiter $limiter,

        /** Whether the SAML protocol is available. */
        private ProtocolManager $protocols,
    ) {}

    /**
     * The settings the metadata given as XML proposes for the entity, held to
     * the connection's anchors when a connection is named.
     *
     * @param  string  $tenantId
     * @param  ?string  $connectionId
     * @param  string  $xml
     * @param  string  $entityId
     * @return \SineMacula\Laravel\Sso\Metadata\ImportResult
     *
     * @throws \InvalidArgumentException
     */
    public function importXml(string $tenantId, ?string $connectionId, #[\SensitiveParameter] string $xml, string $entityId): ImportResult
    {
        $connection = $this->connectionOf($tenantId, $connectionId);

        if ($connection instanceof ImportResult) {
            return $connection;
        }

        return $this->proposal($connection, $xml, $entityId);
    }

    /**
     * The settings the metadata fetched from the URL proposes for the entity,
     * held to the connection's anchors and counted against its limit when a
     * connection is named.
     *
     * @param  string  $tenantId
     * @param  ?string  $connectionId
     * @param  string  $url
     * @param  string  $entityId
     * @return \SineMacula\Laravel\Sso\Metadata\ImportResult
     *
     * @throws \InvalidArgumentException
     */
    public function importUrl(string $tenantId, ?string $connectionId, string $url, string $entityId): ImportResult
    {
        $connection = $this->connectionOf($tenantId, $connectionId);

        if ($connection instanceof ImportResult) {
            return $connection;
        }

        $fetched = $this->fetched($connection, $url);

        if ($fetched instanceof ImportResult) {
            return $fetched;
        }

        $body = $fetched->isSuccessful() ? $fetched->body() : null;

        return $body === null ? ImportResult::refused($fetched->reason ?? FailureReason::FETCH_FAILED) : $this->proposal($connection, $body, $entityId);
    }

    /**
     * The URL fetched as a metadata request held to the metadata cap, once an
     * import of the connection named, if any, is counted against its limit;
     * or the import rate limited.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $url
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult|\SineMacula\Laravel\Sso\Metadata\ImportResult
     *
     * @throws \InvalidArgumentException
     */
    private function fetched(?Connection $connection, string $url): FetchResult|ImportResult
    {
        $attempt = $connection === null ? null : $this->limiter->attempt(AttemptSubject::metadata($connection->id));

        if ($attempt?->isRateLimited() === true) {
            return ImportResult::rateLimited($attempt->retryAfter ?? 1);
        }

        return $this->fetcher->fetch(FetchRequest::metadata($url, $this->reader->maxBytes()));
    }

    /**
     * The tenant's SAML connection named, `null` when none is named, or the
     * refusal of one that is unknown, another tenant's or not SAML, or of any
     * import while the SAML protocol is not available.
     *
     * @param  string  $tenantId
     * @param  ?string  $connectionId
     * @return \SineMacula\Laravel\Sso\Metadata\ImportResult|\SineMacula\Laravel\Sso\Models\Connection|null
     *
     * @throws \InvalidArgumentException
     */
    private function connectionOf(string $tenantId, ?string $connectionId): Connection|ImportResult|null
    {
        if ($tenantId === '' || strlen($tenantId) > ConnectionFinder::MAX_TENANT_ID_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A tenant id is 1 to %d bytes.', ConnectionFinder::MAX_TENANT_ID_LENGTH));
        }

        if (!$this->protocols->isAvailable(Saml2Driver::NAME)) {
            return ImportResult::refused(FailureReason::PROTOCOL_UNAVAILABLE);
        }

        if ($connectionId === null) {
            return null;
        }

        $connection = $this->connections->find($tenantId, $connectionId);

        return $connection?->protocol === Saml2Driver::NAME ? $connection : ImportResult::refused(FailureReason::CONNECTION_NOT_FOUND);
    }

    /**
     * The settings the document proposes for the entity, read with the
     * connection's anchors and binding when there is a connection.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $xml
     * @param  string  $entityId
     * @return \SineMacula\Laravel\Sso\Metadata\ImportResult
     *
     * @throws \InvalidArgumentException
     */
    private function proposal(?Connection $connection, #[\SensitiveParameter] string $xml, string $entityId): ImportResult
    {
        $anchors  = $connection === null ? [] : $this->keys->trustedCertificates($connection->id, KeyUse::METADATA_SIGNING);
        $binding  = $connection?->settings[Saml2Setting::SSO_BINDING->value] ?? null;
        $pems     = array_map(static fn (KeySummary $anchor): ?string => $anchor->key->certificate, $anchors);
        $metadata = $this->reader->read(
            $xml,
            $entityId,
            array_values(array_filter($pems, static fn (?string $pem): bool => $pem !== null)),
            is_string($binding) ? $binding : null,
        );

        return self::proposed($metadata);
    }

    /**
     * The proposal of the metadata read, or why there is none: the metadata
     * refused, or what it proposes not settings a connection may hold.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @return \SineMacula\Laravel\Sso\Metadata\ImportResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function proposed(IdpMetadata $metadata): ImportResult
    {
        if (!$metadata->isRead()) {
            return ImportResult::refused($metadata->reason ?? FailureReason::METADATA_INVALID, $metadata->detail);
        }

        $proposed = ProposedSettings::of($metadata);

        if (Saml2Settings::fromArray($proposed->settings())->violations() !== []) {
            return ImportResult::refused(FailureReason::METADATA_INVALID, 'settings');
        }

        return ImportResult::proposed($proposed);
    }
}
