<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Endpoints;

use SineMacula\Laravel\Sso\Config\UrlSetting;
use SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint;

/**
 * A connection's endpoints (SSO-5.5), as `Contracts\EndpointResolver` answers
 * them: its SAML assertion consumer service, its OIDC callback, its service
 * provider entity id and its metadata URL.
 *
 * Each must be an absolute `https` URL, or `http` on `127.0.0.1` or `[::1]` for
 * development, with no user information, fragment or wildcard
 * (`Config\UrlSetting::web()`); anything else fails closed with an
 * `InvalidArgumentException` when the value is built, naming the endpoint and
 * never the URL, so a resolver can never publish or check an endpoint a
 * response could be addressed to elsewhere. Each is used exactly as built.
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
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The SAML assertion consumer service, `Destination` and `Recipient` compared with it exactly. */
        public string $assertionConsumerService,

        /** The OIDC callback, sent as `redirect_uri`. */
        public string $callback,

        /** The service provider entity id, the `Issuer` of an `AuthnRequest` and the audience an assertion must name. */
        public string $entityId,

        /** The URL the service provider metadata is published at. */
        public string $metadata,
    ) {
        UrlSetting::web('endpoints.assertion_consumer_service', $assertionConsumerService);
        UrlSetting::web('endpoints.callback', $callback);
        UrlSetting::web('endpoints.entity_id', $entityId);
        UrlSetting::web('endpoints.metadata', $metadata);
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
        };
    }

    /**
     * The endpoints with snake_case keys, as an administrator registers them at
     * the identity provider.
     *
     * @return array{assertion_consumer_service: string, callback: string, entity_id: string, metadata: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'assertion_consumer_service' => $this->assertionConsumerService,
            'callback'                   => $this->callback,
            'entity_id'                  => $this->entityId,
            'metadata'                   => $this->metadata,
        ];
    }
}
