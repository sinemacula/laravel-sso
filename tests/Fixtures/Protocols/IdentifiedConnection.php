<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Protocols;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;

/**
 * A connection held in memory with the id and tenant given, for testing what
 * builds on a connection's id without a database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentifiedConnection implements SsoConnection
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  array<string, mixed>  $settings
     */
    public function __construct(

        /** The id. */
        private string $id,

        /** The tenant. */
        private string $tenantId = 'tenant-1',

        /** The protocol. */
        private string $protocol = 'oidc',

        /** The settings. */
        private array $settings = [],
    ) {}

    /**
     * The id given.
     *
     * @return string
     */
    #[\Override]
    public function getConnectionId(): string
    {
        return $this->id;
    }

    /**
     * The tenant given.
     *
     * @return string
     */
    #[\Override]
    public function getTenantId(): string
    {
        return $this->tenantId;
    }

    /**
     * The protocol given.
     *
     * @return string
     */
    #[\Override]
    public function getProtocol(): string
    {
        return $this->protocol;
    }

    /**
     * A fixed name.
     *
     * @return string
     */
    #[\Override]
    public function getDisplayName(): string
    {
        return 'Identified';
    }

    /**
     * The settings given, none by default.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function getSettings(): array
    {
        return $this->settings;
    }

    /**
     * No mapping.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function getAttributeMapping(): array
    {
        return [];
    }

    /**
     * Enabled.
     *
     * @return bool
     */
    #[\Override]
    public function isEnabled(): bool
    {
        return true;
    }

    /**
     * Never.
     *
     * @return bool
     */
    #[\Override]
    public function hasCompletedSignIn(): bool
    {
        return false;
    }
}
