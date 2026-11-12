<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Imports an OpenID provider's discovery document and JWKS and proposes
 * settings for an administrator to review; it writes and trusts nothing.
 *
 * Call outside any transaction on the storage connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DiscoveryImporter
{
    /** @var string What is appended to an issuer to find its discovery document. */
    private const string DISCOVERY_PATH = '/.well-known/openid-configuration';

    /** @var string Why an import refuses to run inside a transaction. */
    private const string IN_TRANSACTION = 'A discovery import runs outside any transaction on the storage connection, since it fetches while it is called.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $connections
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Contracts\Fetcher  $fetcher
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits  $limits
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Whether the OIDC protocol is available. */
        private ProtocolManager $protocols,

        /** Finds the tenant's connection, on the write connection. */
        private ConnectionFinder $connections,

        /** Limits how often a connection's discovery document is imported. */
        private AttemptLimiter $limiter,

        /** Fetches the discovery document and the JWKS. */
        private Fetcher $fetcher,

        /** The caps on the discovery document and the JWKS. */
        private OidcLimits $limits,

        /** The clock each validated moment is read from. */
        private Clock $clock,
    ) {}

    /**
     * The settings the issuer's discovery document proposes, held to the named
     * connection's allow-list and counted against its limit.
     *
     * @param  string  $tenantId
     * @param  string  $issuer
     * @param  ?string  $connectionId
     * @return \SineMacula\Laravel\Sso\Metadata\DiscoveryImport
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function import(string $tenantId, string $issuer, ?string $connectionId = null): DiscoveryImport
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        $connection = $this->connectionOf($tenantId, $issuer, $connectionId);

        if ($connection instanceof DiscoveryImport) {
            return $connection;
        }

        $attempt = $connection === null ? null : $this->limiter->attempt(AttemptSubject::metadata($connection->id));

        if ($attempt?->isRateLimited() === true) {
            /** @var int $retryAfter */
            $retryAfter = $attempt->retryAfter;

            return DiscoveryImport::rateLimited($retryAfter);
        }

        return self::proposal($this->fetch($issuer, $connection === null ? null : OidcOptions::of($connection)->algorithms()));
    }

    /**
     * Fetch and validate the issuer's discovery document, then its JWKS under
     * the allow-list or, with none, the document's own algorithms.
     *
     * @param  string  $issuer
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return \SineMacula\Laravel\Sso\Metadata\FetchedMetadata
     *
     * @throws \InvalidArgumentException
     */
    public function fetch(string $issuer, ?AlgorithmAllowList $allowed): FetchedMetadata
    {
        $maxBytes = $this->limits->maxDiscoveryBytes();
        $fetched  = $this->fetcher->fetch(FetchRequest::discovery(rtrim($issuer, '/') . self::DISCOVERY_PATH, $maxBytes));

        if (!$fetched->isSuccessful()) {
            return FetchedMetadata::refused($fetched->reason ?? FailureReason::FETCH_FAILED, $fetched->status);
        }

        $document = DiscoveryDocument::read((string) $fetched->body(), $issuer, $maxBytes);

        if (!$document->isRead()) {
            return FetchedMetadata::refused($document->reason ?? FailureReason::DISCOVERY_INVALID, $fetched->status);
        }

        // The moment the document was validated, read once the reader is done
        return $this->withKeys($document, $allowed ?? AlgorithmAllowList::of($document->algorithms()), $this->clock->now());
    }

    /**
     * Fetch and validate the JWKS at the URL under the allow-list, with no
     * discovery document.
     *
     * @param  string  $jwksUri
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return \SineMacula\Laravel\Sso\Metadata\FetchedMetadata
     *
     * @throws \InvalidArgumentException
     */
    public function fetchKeys(string $jwksUri, AlgorithmAllowList $allowed): FetchedMetadata
    {
        $maxBytes = $this->limits->maxJwksBytes();
        $fetched  = $this->fetcher->fetch(FetchRequest::jwks($jwksUri, $maxBytes));

        if (!$fetched->isSuccessful()) {
            return FetchedMetadata::refused($fetched->reason ?? FailureReason::FETCH_FAILED, $fetched->status);
        }

        $keys = ProviderKeySet::read((string) $fetched->body(), $allowed, $maxBytes, $this->limits->maxJwksKeys());

        return $keys === null ? FetchedMetadata::refused(FailureReason::JWKS_INVALID, $fetched->status) : FetchedMetadata::read($keys, $this->clock->now());
    }

    /**
     * The tenant's OIDC connection named, `null` when none is named, or the
     * refusal of the import.
     *
     * @param  string  $tenantId
     * @param  string  $issuer
     * @param  ?string  $connectionId
     * @return \SineMacula\Laravel\Sso\Metadata\DiscoveryImport|\SineMacula\Laravel\Sso\Models\Connection|null
     *
     * @throws \InvalidArgumentException
     */
    private function connectionOf(string $tenantId, string $issuer, ?string $connectionId): Connection|DiscoveryImport|null
    {
        if ($tenantId === '' || strlen($tenantId) > ConnectionFinder::MAX_TENANT_ID_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A tenant id is 1 to %d bytes.', ConnectionFinder::MAX_TENANT_ID_LENGTH));
        }

        $refusal = $this->refusal($issuer);

        if ($refusal !== null || $connectionId === null) {
            return $refusal;
        }

        $connection = $this->connections->find($tenantId, $connectionId);

        return $connection?->protocol === OidcDriver::NAME ? $connection : DiscoveryImport::refused(FailureReason::CONNECTION_NOT_FOUND);
    }

    /**
     * Why no import of the issuer may start, or `null` when one may.
     *
     * @param  string  $issuer
     * @return ?\SineMacula\Laravel\Sso\Metadata\DiscoveryImport
     *
     * @throws \InvalidArgumentException
     */
    private function refusal(string $issuer): ?DiscoveryImport
    {
        if (!$this->protocols->isAvailable(OidcDriver::NAME)) {
            return DiscoveryImport::refused(FailureReason::PROTOCOL_UNAVAILABLE);
        }

        $violations = OidcSettings::fromArray([OidcSetting::ISSUER->value => $issuer])->violations();

        return $violations === [] ? null : DiscoveryImport::refused(FailureReason::SETTINGS_INVALID);
    }

    /**
     * The document with its JWKS fetched under the allow-list, or why there is
     * none.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\DiscoveryDocument  $document
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @return \SineMacula\Laravel\Sso\Metadata\FetchedMetadata
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function withKeys(DiscoveryDocument $document, AlgorithmAllowList $allowed, CarbonImmutable $validatedAt): FetchedMetadata
    {
        $fetched = $this->fetchKeys($document->jwksUri(), $allowed);
        $keys    = $fetched->document();

        if (!$keys instanceof ProviderKeySet || $fetched->validatedAt === null) {
            return $fetched;
        }

        return FetchedMetadata::read(new OidcMetadata($document, $keys, $fetched->validatedAt), $validatedAt);
    }

    /**
     * The proposal of what was fetched, or why there is none.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\FetchedMetadata  $fetched
     * @return \SineMacula\Laravel\Sso\Metadata\DiscoveryImport
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function proposal(FetchedMetadata $fetched): DiscoveryImport
    {
        $metadata = $fetched->document();

        if (!$metadata instanceof OidcMetadata || $fetched->validatedAt === null) {
            return DiscoveryImport::refused($fetched->reason ?? FailureReason::DISCOVERY_INVALID);
        }

        return DiscoveryImport::proposed(ProposedOidcSettings::of($metadata->document(), $metadata->keys(), $fetched->validatedAt));
    }
}
