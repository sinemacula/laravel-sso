<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
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
 * An OIDC connection using `private_key_jwt` is described naming its public
 * JWKS URL (`jwks_uri`), so a rotation needs no re-registration; a provider
 * that requires uploaded keys is given `describeWithInlineKeys()` instead, the
 * same document with the keys in it, never both in one document, and must be
 * given it again whenever a next key is added or made current. `publicKeys()`
 * answers the body the application serves at that URL: its current and next
 * public keys, named by the connection's id alone, of any tenant, since the
 * provider that fetches the URL names no tenant, and a connection with nothing
 * to serve is answered as an unknown one. The package adds no route. Each of
 * these answers `connection_unavailable` for a protocol that has no such keys.
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
    /** @var int The length of a connection's id, a ULID: a longer one names no connection. */
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
        $refusal    = $this->refusal($connection);

        if ($connection === null || $refusal !== null) {
            return ServiceProviderDescription::unavailable($refusal ?? FailureReason::CONNECTION_UNAVAILABLE);
        }

        return $this->protocols->protocol($connection->getProtocol())->describe($connection);
    }

    /**
     * Describe the tenant's OIDC connection with its public keys in the
     * document, for a provider that requires uploaded keys.
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
     * The body the application serves at the connection's public JWKS URL,
     * whichever tenant it belongs to: its current and next public keys.
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
     * Why the connection cannot be described at all, or `null`: it is gone, or
     * its protocol is not available.
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
     * The answer for a connection with no OIDC driver available: why it cannot
     * be described, or `connection_unavailable` for a protocol that has no such
     * keys.
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
     * The connection with exactly the id, of any tenant, from the write
     * connection; `null` when there is none. An id longer than a ULID, or
     * empty, names none and is not looked up; a row the column's collation
     * merely counts as equal is not found.
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
