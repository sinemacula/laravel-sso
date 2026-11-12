<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Endpoints;

use SineMacula\Laravel\Sso\Config\UrlSetting;
use SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint;

/**
 * A connection's endpoints, as `Contracts\EndpointResolver` answers them.
 *
 * Each is validated as a web URL on construction and used exactly as built.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConnectionEndpoints implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $assertionConsumerService
     * @param  string  $callback
     * @param  string  $entityId
     * @param  string  $metadata
     * @param  string  $jwks
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The SAML assertion consumer service; `Destination` and `Recipient` must match it exactly. */
        public string $assertionConsumerService,

        /** The OIDC callback, sent as `redirect_uri`. */
        public string $callback,

        /** The service provider entity id: the `AuthnRequest` issuer and required audience. */
        public string $entityId,

        /** The service provider metadata URL. */
        public string $metadata,

        /** The OIDC client assertion keys' `jwks_uri`. */
        public string $jwks,
    ) {
        UrlSetting::web('endpoints.assertion_consumer_service', $assertionConsumerService);
        UrlSetting::web('endpoints.callback', $callback);
        UrlSetting::web('endpoints.entity_id', $entityId);
        UrlSetting::web('endpoints.metadata', $metadata);
        UrlSetting::web('endpoints.jwks', $jwks);
    }

    /**
     * The URL of the endpoint.
     *
     * @param  \SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint  $endpoint
     * @return string
     */
    public function url(Endpoint $endpoint): string
    {
        return match ($endpoint) {
            Endpoint::ASSERTION_CONSUMER_SERVICE => $this->assertionConsumerService,
            Endpoint::CALLBACK                   => $this->callback,
            Endpoint::METADATA                   => $this->metadata,
            Endpoint::JWKS                       => $this->jwks,
        };
    }

    /**
     * The endpoints with snake_case keys.
     *
     * @return array{assertion_consumer_service: string, callback: string, entity_id: string, metadata: string, jwks: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'assertion_consumer_service' => $this->assertionConsumerService,
            'callback'                   => $this->callback,
            'entity_id'                  => $this->entityId,
            'metadata'                   => $this->metadata,
            'jwks'                       => $this->jwks,
        ];
    }
}
