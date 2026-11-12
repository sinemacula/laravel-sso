<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;

/**
 * Describes what an administrator registers at a connection's identity
 * provider, for the application to serve or show.
 *
 * Reads public data only, so it asks for no fresh authentication.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ServiceProviderDescriptions
{
    /** @var int The length of a connection's id, a ULID. */
    private const int CONNECTION_ID_LENGTH = 26;

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
     * Describes disabled and incomplete connections too, so they can be
     * registered before they are enabled.
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
        $refusal    = $this->refusal($connection);

        if ($connection === null || $refusal !== null) {
            return ServiceProviderDescription::unavailable($refusal ?? FailureReason::CONNECTION_UNAVAILABLE);
        }

        return $this->protocols->protocol($connection->getProtocol())->describe($connection);
    }

    /**
     * Describe the OIDC connection with its public keys inline, for a provider
     * that requires uploaded keys; give it again after each key rotation.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function describeWithInlineKeys(string $tenantId, string $connectionId): ServiceProviderDescription
    {
        $connection = $this->connections->find($tenantId, $connectionId);
        $driver     = $this->oidcDriverOf($connection);

        return $connection === null || !$driver instanceof OidcDriver ? $this->unavailable($connection) : $driver->describeWithInlineKeys($connection);
    }

    /**
     * The body served at the connection's public JWKS URL, looked up by id
     * alone since the fetching provider names no tenant.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function publicKeys(string $connectionId): ServiceProviderDescription
    {
        $connection = self::connectionOfAnyTenant($connectionId);
        $driver     = $this->oidcDriverOf($connection);

        return $connection === null || !$driver instanceof OidcDriver ? $this->unavailable($connection) : $driver->publicKeys($connection);
    }

    /**
     * Why the connection cannot be described at all, or `null`.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     */
    private function refusal(?Connection $connection): ?FailureReason
    {
        return match (true) {
            $connection === null                                       => FailureReason::CONNECTION_UNAVAILABLE,
            !$this->protocols->isAvailable($connection->getProtocol()) => FailureReason::PROTOCOL_UNAVAILABLE,
            default                                                    => null,
        };
    }

    /**
     * The connection's driver, when it is the OIDC driver and available.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function oidcDriverOf(?Connection $connection): ?OidcDriver
    {
        if ($connection === null || $this->refusal($connection) !== null) {
            return null;
        }

        $driver = $this->protocols->protocol($connection->getProtocol());

        return $driver instanceof OidcDriver ? $driver : null;
    }

    /**
     * The refusal, or `connection_unavailable` for a protocol without keys.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     *
     * @throws \InvalidArgumentException
     */
    private function unavailable(?Connection $connection): ServiceProviderDescription
    {
        return ServiceProviderDescription::unavailable($this->refusal($connection) ?? FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * The connection with exactly the id, of any tenant, ignoring rows the
     * collation merely counts as equal.
     *
     * @param  string  $connectionId
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private static function connectionOfAnyTenant(string $connectionId): ?Connection
    {
        if ($connectionId === '' || strlen($connectionId) > self::CONNECTION_ID_LENGTH) {
            return null;
        }

        $connection = Connection::query()->useWritePdo()->whereKey($connectionId)->first();

        return $connection?->id === $connectionId ? $connection : null;
    }
}
