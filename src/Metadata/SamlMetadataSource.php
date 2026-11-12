<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataReader;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;

/**
 * What a SAML connection refreshes: its identity provider's metadata, from the
 * `metadata_url` the administrator saved and no other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SamlMetadataSource extends MetadataSource
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaims  $claims
     * @param  \SineMacula\Laravel\Sso\Contracts\Fetcher  $fetcher
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataReader  $reader
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataApplier  $applier
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \Psr\Log\LoggerInterface  $logger
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The connection's anchors and trusted certificates. */
        private KeyRing $keys,

        /** Claims the connection's refresh. */
        private RefreshClaims $claims,

        /** Fetches the metadata URL. */
        private Fetcher $fetcher,

        /** Reads the metadata for the pinned entity. */
        private MetadataReader $reader,

        /** Writes the refresh or its failure under the connection's lock. */
        private MetadataApplier $applier,

        /** The clock the moment of validation is read from. */
        private Clock $clock,

        /** The sanitising logger a contained exception is logged to. */
        private LoggerInterface $logger,
    ) {}

    /**
     * The SAML protocol.
     *
     * @return string
     */
    #[\Override]
    public function protocol(): string
    {
        return Saml2Driver::NAME;
    }

    /**
     * Whether the schedule refreshes the connection's metadata: it has an
     * `https` URL and opted in, or has an anchor and did not opt out.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    #[\Override]
    public function refreshes(Connection $connection): bool
    {
        return $connection->protocol === Saml2Driver::NAME && SamlRefreshRule::refreshes($connection);
    }

    /**
     * Those of the connections the schedule refreshes, in the order given,
     * their anchors read once.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     */
    #[\Override]
    public function refreshing(array $connections): array
    {
        $saml     = array_values(array_filter($connections, $this->isRefreshable(...)));
        $anchored = SamlRefreshRule::anchoredAmong($saml);

        return array_values(array_filter($saml, static fn (Connection $connection): bool => SamlRefreshRule::refreshes($connection, isset($anchored[$connection->id]))));
    }

    /**
     * Whether the connection is SAML with an `https` `metadata_url`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    #[\Override]
    public function isRefreshable(Connection $connection): bool
    {
        return $connection->protocol === Saml2Driver::NAME && SamlRefreshRule::hasUrl($connection->settings);
    }

    /**
     * Snapshot the connection's anchors and certificates and claim its refresh.
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
        $anchors = $this->keys->trustedCertificates($connection->id, KeyUse::METADATA_SIGNING);
        $trusted = RefreshClaim::trustedOf($this->keys->trustedCertificates($connection->id), $anchors);

        return $this->claims->claim($connection, $trusted, self::certificates($anchors));
    }

    /**
     * Fetch the saved URL and read the metadata of the pinned entity with the
     * claim's anchors, noting the moment it validated.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return \SineMacula\Laravel\Sso\Metadata\FetchedMetadata
     */
    #[\Override]
    public function fetch(RefreshClaim $claim): FetchedMetadata
    {
        $connection = $claim->connection;
        $fetched    = $this->fetcher->fetch(FetchRequest::metadata(self::setting($connection, Saml2Setting::METADATA_URL), $this->reader->maxBytes()));

        if (!$fetched->isSuccessful()) {
            return FetchedMetadata::refused($fetched->reason ?? FailureReason::FETCH_FAILED, $fetched->status);
        }

        $metadata = $this->read($connection, (string) $fetched->body(), $claim->anchors);

        if (!$metadata->isRead()) {
            return FetchedMetadata::refused($metadata->reason ?? FailureReason::METADATA_INVALID, $fetched->status);
        }

        // The moment the document was validated, read once the reader is done
        return FetchedMetadata::read($metadata, $this->clock->now());
    }

    /**
     * Apply the metadata, or record the failure, through the applier.
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
        $metadata = $fetched->document();

        if (!$metadata instanceof IdpMetadata || $fetched->validatedAt === null) {
            return $this->applier->fail($claim, $fetched->reason ?? FailureReason::METADATA_INVALID, $client, $caller);
        }

        return $this->applier->apply($claim, $metadata, $fetched->validatedAt, $client, $caller);
    }

    /**
     * The metadata of the connection's pinned entity, read with the anchors; a
     * reader that throws is contained so a run goes on to the next connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $xml
     * @param  list<string>  $anchors
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
     */
    private function read(Connection $connection, #[\SensitiveParameter] string $xml, array $anchors): IdpMetadata
    {
        try {
            return $this->reader->read($xml, self::setting($connection, Saml2Setting::IDP_ENTITY_ID), $anchors, self::setting($connection, Saml2Setting::SSO_BINDING));
        } catch (\Throwable $exception) {
            $this->logger->warning('sso.metadata.refresh_contained', ['exception' => $exception::class]);

            return IdpMetadata::refused(FailureReason::METADATA_INVALID, 'unreadable');
        }
    }

    /**
     * The PEM certificates of the anchors.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $anchors
     * @return list<string>
     */
    private static function certificates(array $anchors): array
    {
        $certificates = [];

        foreach ($anchors as $anchor) {
            if ($anchor->key->certificate === null) {
                continue;
            }

            $certificates[] = $anchor->key->certificate;
        }

        return $certificates;
    }

    /**
     * The connection's setting as a string, empty when it holds none.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting  $setting
     * @return string
     */
    private static function setting(Connection $connection, Saml2Setting $setting): string
    {
        $value = $connection->settings[$setting->value] ?? null;

        return is_string($value) ? $value : '';
    }
}
