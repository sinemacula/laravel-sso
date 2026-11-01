<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Secrets\MaskedSecret;

/**
 * What a management helper returns for a connection (SSO-2.5, SSO-2.11): its
 * id, tenant and protocol, its display name, its settings, each secret its
 * protocol declares masked as `Secrets\MaskedSecret` (set or not, and nothing
 * of it), its attribute mapping, whether it is enabled, whether a sign-in
 * through it has been completed, whether it is usable now (SSO-2.1), and when
 * it was created and last changed.
 *
 * It never holds a secret or a ciphertext: the settings hold none, and the
 * secrets are read by name alone, without decrypting one. A connection whose
 * protocol is not registered declares no secrets and is never usable.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConnectionSummary implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  string  $displayName
     * @param  array<string, mixed>  $settings
     * @param  array<string, \SineMacula\Laravel\Sso\Secrets\MaskedSecret>  $secrets
     * @param  array<string, mixed>  $attributeMapping
     * @param  bool  $enabled
     * @param  bool  $hasCompletedSignIn
     * @param  bool  $usable
     * @param  \Carbon\CarbonImmutable  $createdAt
     * @param  \Carbon\CarbonImmutable  $updatedAt
     */
    public function __construct(

        /** The connection's id, the `{connection}` of its endpoints. */
        public string $id,

        /** The opaque id of the tenant it belongs to. */
        public string $tenantId,

        /** The protocol it runs over. */
        public string $protocol,

        /** The name administrators know it by. */
        public string $displayName,

        /** Its settings by name, with no secret among them. */
        public array $settings,

        /** Each secret its protocol declares, masked, by name. */
        public array $secrets,

        /** Each target attribute by the attribute or claim it is read from. */
        public array $attributeMapping,

        /** Whether it is enabled. */
        public bool $enabled,

        /** Whether a sign-in through it has been completed. */
        public bool $hasCompletedSignIn,

        /** Whether it may be used now: enabled, its protocol available and its settings complete. */
        public bool $usable,

        /** When it was created, in UTC. */
        public CarbonImmutable $createdAt,

        /** When it last changed, in UTC. */
        public CarbonImmutable $updatedAt,
    ) {}

    /**
     * The summary of the connection, its secrets masked by the names its
     * protocol declares and its usability read from the protocols.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSecrets  $secrets
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public static function of(Connection $connection, ProtocolManager $protocols, ConnectionSecrets $secrets): self
    {
        $protocol = $connection->protocol;
        $names    = $protocols->isRegistered($protocol) ? $protocols->protocol($protocol)->settings([])::secretNames() : [];

        return new self(
            id: $connection->id,
            tenantId: $connection->tenant_id,
            protocol: $protocol,
            displayName: $connection->display_name,
            settings: $connection->settings,
            secrets: $secrets->masked($connection, $names),
            attributeMapping: $connection->attribute_mapping,
            enabled: $connection->enabled,
            hasCompletedSignIn: $connection->has_completed_sign_in,
            usable: $protocols->isUsable($connection),
            createdAt: $connection->created_at->utc(),
            updatedAt: $connection->updated_at->utc(),
        );
    }

    /**
     * The summary, with snake_case keys, each secret as whether it is set, and
     * each time as an ISO 8601 UTC string.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'id'                    => $this->id,
            'tenant_id'             => $this->tenantId,
            'protocol'              => $this->protocol,
            'display_name'          => $this->displayName,
            'settings'              => self::map($this->settings),
            'secrets'               => self::map(array_map(static fn (MaskedSecret $secret): array => $secret->jsonSerialize(), $this->secrets)),
            'attribute_mapping'     => self::map($this->attributeMapping),
            'enabled'               => $this->enabled,
            'has_completed_sign_in' => $this->hasCompletedSignIn,
            'usable'                => $this->usable,
            'created_at'            => $this->createdAt->utc()->format('Y-m-d\TH:i:s\Z'),
            'updated_at'            => $this->updatedAt->utc()->format('Y-m-d\TH:i:s\Z'),
        ];
    }

    /**
     * A map, encoded as a JSON object even when it is empty.
     *
     * @param  array<string, mixed>  $map
     * @return array<string, mixed>|\stdClass
     */
    private static function map(array $map): array|\stdClass
    {
        return $map === [] ? new \stdClass : $map;
    }
}
