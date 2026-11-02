<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;

/**
 * What an administrator registers at a connection's identity provider
 * (SSO-5.9), for an application to serve or show: a SAML connection's service
 * provider metadata, or what its protocol's driver describes for any other
 * protocol, as a `Protocols\ServiceProviderDescription`.
 *
 * - A connection the tenant does not have, unknown or another tenant's, is
 *   `connection_unavailable`, the same answer for both, so the helper never
 *   reveals another tenant's connection (`ConnectionFinder`).
 * - A connection whose protocol is not available (no driver is registered under
 *   it, or its feature is off) is `protocol_unavailable`.
 * - Any other connection is described by its protocol's driver, whatever it
 *   holds: a disabled connection, or one whose identity provider settings are
 *   not yet complete, is described too, so an administrator can register it at
 *   the identity provider before enabling it.
 *
 * It reads public data and changes nothing, so it asks for no fresh
 * authentication. The connection is read from the write connection (SSO-11.3);
 * a database error propagates (SSO-11.4), and an empty or overlong tenant id is
 * an `InvalidArgumentException`. Nothing is kept between calls (SSO-11.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ServiceProviderDescriptions
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $connections
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     */
    public function __construct(

        /** Finds the tenant's connection. */
        private ConnectionFinder $connections,

        /** Resolves the connection's protocol driver. */
        private ProtocolManager $protocols,
    ) {}

    /**
     * Describe the service provider side of the tenant's connection.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function describe(string $tenantId, string $connectionId): ServiceProviderDescription
    {
        $connection = $this->connections->find($tenantId, $connectionId);

        if ($connection === null) {
            return ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE);
        }

        $protocol = $connection->getProtocol();

        if (!$this->protocols->isAvailable($protocol)) {
            return ServiceProviderDescription::unavailable(FailureReason::PROTOCOL_UNAVAILABLE);
        }

        return $this->protocols->protocol($protocol)->describe($connection);
    }
}
