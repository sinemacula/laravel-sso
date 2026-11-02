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
 * Describes a SAML connection's service provider side as SAML 2.0 Metadata
 * (SSO-5.9), `application/samlmetadata+xml`: its entity id and assertion
 * consumer service from the endpoint resolver (SSO-5.5), the certificates of
 * its published signing and encryption keys (`KeyRing::published()`: the
 * current key, then the next one during a rotation), its NameID format, its
 * `AuthnRequestsSigned` and `WantAssertionsSigned` switches, and the encryption
 * methods it allows, written by `Library\MetadataWriter`.
 *
 * Only the service provider side is described, so a connection whose identity
 * provider settings are not yet given is described too, for an administrator to
 * register it first. A key published with no certificate is left out. It holds
 * no private key and no secret, and is not signed. Every value is read afresh
 * on each call, and nothing is kept between calls (SSO-11.2).
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
     * The certificate of each published key of the use, the current key first.
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
