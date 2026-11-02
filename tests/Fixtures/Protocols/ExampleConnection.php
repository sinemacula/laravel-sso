<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Protocols;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;

/**
 * A connection held in memory, for testing what reads one through its contract
 * without a database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExampleConnection implements SsoConnection
{
    /**
     * Constructor.
     *
     * @param  string  $protocol
     * @param  array<string, mixed>  $settings
     * @param  bool  $enabled
     * @param  ?array<string, bool|int|string|null>  $linking
     */
    public function __construct(

        /** The protocol. */
        private string $protocol = 'example',

        /** The settings. */
        private array $settings = [],

        /** Whether it is enabled. */
        private bool $enabled = true,

        /** The linking settings it states, when not those of linking off. */
        private ?array $linking = null,
    ) {}

    /**
     * A fixed id.
     *
     * @return string
     */
    #[\Override]
    public function getConnectionId(): string
    {
        return '01jbexampleconnection00000';
    }

    /**
     * A fixed tenant.
     *
     * @return string
     */
    #[\Override]
    public function getTenantId(): string
    {
        return 'tenant-1';
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
        return 'Example';
    }

    /**
     * The settings given.
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
     * Whether it is enabled.
     *
     * @return bool
     */
    #[\Override]
    public function isEnabled(): bool
    {
        return $this->enabled;
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

    /**
     * No settings for linking by a verified domain: off.
     *
     * @return array<string, bool|int|string|null>
     */
    #[\Override]
    public function getLinkingSettings(): array
    {
        return $this->linking ?? [
            'enabled'               => false,
            'issuer_class'          => null,
            'organization_claim'    => null,
            'organization_value'    => null,
            'saml_attribute'        => null,
            'saml_attribute_format' => null,
            'acknowledged'          => false,
            'version'               => 0,
        ];
    }

    /**
     * Nothing is accepted as evidence.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function getEvidencePolicy(): array
    {
        return [];
    }
}
