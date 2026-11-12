<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataWriter;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;

/**
 * Describes a SAML connection's service provider side as unsigned SAML 2.0
 * Metadata, so it can be registered before the IdP settings are given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ServiceProviderMetadata
{
    /** @var string The media type of SAML 2.0 Metadata. */
    public const string CONTENT_TYPE = 'application/samlmetadata+xml';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  \SineMacula\Laravel\Sso\Contracts\EndpointResolver  $endpoints
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataWriter  $writer
     */
    public function __construct(

        /** The connection's published keys. */
        private KeyRing $keys,

        /** Builds the connection's entity id and assertion consumer service. */
        private EndpointResolver $endpoints,

        /** Writes the metadata. */
        private MetadataWriter $writer,
    ) {}

    /**
     * Describe the connection's service provider side.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     */
    public function describe(SsoConnection $connection, Saml2Options $options): ServiceProviderDescription
    {
        $id  = $connection->getConnectionId();
        $xml = $this->writer->write(
            $this->endpoints->endpoints($connection),
            $options,
            $this->certificates($id, KeyUse::SP_SIGNING),
            $this->certificates($id, KeyUse::SP_ENCRYPTION),
        );

        return ServiceProviderDescription::document(self::CONTENT_TYPE, $xml);
    }

    /**
     * The certificate of each published key of the use, current key first;
     * keys without one are skipped.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function certificates(string $connectionId, KeyUse $use): array
    {
        $certificates = array_map(static fn (KeySummary $key): ?string => $key->key->certificate, $this->keys->published($connectionId, $use));

        return array_values(array_filter($certificates, is_string(...)));
    }
}
