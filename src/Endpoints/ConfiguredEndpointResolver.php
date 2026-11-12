<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Endpoints;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint;

/**
 * The default endpoint resolver: the base URL plus each path pattern, with the
 * entity id as the metadata URL.
 *
 * Nothing is read from the request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredEndpointResolver implements EndpointResolver
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the base URL and the patterns are read from. */
        private Repository $config,
    ) {}

    /**
     * The connection's endpoints, built from the configuration and its id.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function endpoints(SsoConnection $connection): ConnectionEndpoints
    {
        $id = $connection->getConnectionId();

        if ($id === '') {
            throw new \InvalidArgumentException('A connection\'s endpoints are built from its id, which is empty.');
        }

        $settings = new EndpointSettings($this->config);
        $base     = rtrim($settings->baseUrl(), '/');
        $build    = static fn (Endpoint $endpoint): string => $base . str_replace(EndpointSettings::PLACEHOLDER, rawurlencode($id), $settings->pattern($endpoint));
        $metadata = $build(Endpoint::METADATA);

        return new ConnectionEndpoints($build(Endpoint::ASSERTION_CONSUMER_SERVICE), $build(Endpoint::CALLBACK), $metadata, $metadata, $build(Endpoint::JWKS));
    }
}
