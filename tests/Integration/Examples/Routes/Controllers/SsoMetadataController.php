<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Controllers;

use Illuminate\Http\Response;
use SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions;
use Tests\Integration\Examples\Routes\Application\ConnectionTenants;

/**
 * The example application's public metadata and JWKS routes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoMetadataController
{
    /**
     * Describe connections through the package's helper.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ServiceProviderDescriptions  $descriptions
     * @param  \Tests\Integration\Examples\Routes\Application\ConnectionTenants  $tenants
     */
    public function __construct(

        /** Describes a connection's service provider side. */
        private ServiceProviderDescriptions $descriptions,

        /** The application's record of each connection's tenant. */
        private ConnectionTenants $tenants,
    ) {}

    /**
     * `GET /auth/sso/connections/{connection}/metadata`: what an administrator
     * registers at the identity provider.
     *
     * @param  string  $connection
     * @return \Illuminate\Http\Response
     */
    public function metadata(string $connection): Response
    {
        // @snippet-start route-metadata
        $tenantId    = $this->tenants->of($connection);
        $description = $tenantId === null ? null : $this->descriptions->describe($tenantId, $connection);

        if ($description === null || !$description->isAvailable()) {
            abort(404);
        }

        return response((string) $description->body, 200, [
            'Content-Type'  => (string) $description->contentType,
            'Cache-Control' => 'public, max-age=3600',
        ]);
        // @snippet-end route-metadata
    }

    /**
     * `GET /auth/sso/connections/{connection}/jwks`: an OIDC connection's
     * public keys, for `private_key_jwt`.
     *
     * @param  string  $connection
     * @return \Illuminate\Http\Response
     */
    public function jwks(string $connection): Response
    {
        // @snippet-start route-jwks
        $keys = $this->descriptions->publicKeys($connection);

        if (!$keys->isAvailable()) {
            abort(404);
        }

        return response((string) $keys->body, 200, ['Content-Type' => (string) $keys->contentType, 'Cache-Control' => 'public, max-age=300']);
        // @snippet-end route-jwks
    }
}
