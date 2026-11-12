<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * A tenant's trust in one identity provider over one protocol.
 *
 * Only the class name is public API; drivers read it through
 * `Contracts\SsoConnection`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $tenant_id
 * @property string $protocol
 * @property string $display_name
 * @property array<string, mixed> $settings
 * @property ?string $secrets
 * @property array<string, mixed> $attribute_mapping
 * @property bool $enabled
 * @property bool $has_completed_sign_in
 * @property int $links_version
 * @property int $flows_version
 * @property int $trust_version
 * @property bool $linking_enabled
 * @property ?string $linking_issuer_class
 * @property ?string $linking_organization_claim
 * @property ?string $linking_organization_value
 * @property ?string $linking_saml_attribute
 * @property ?string $linking_saml_attribute_format
 * @property ?\Carbon\CarbonImmutable $linking_acknowledged_at
 * @property int $linking_version
 * @property ?array<string, mixed> $evidence_policy
 * @property int $metadata_version
 * @property ?\Carbon\CarbonImmutable $metadata_fetched_at
 * @property ?\Carbon\CarbonImmutable $metadata_valid_until
 * @property ?\Carbon\CarbonImmutable $metadata_refresh_at
 * @property int $metadata_refresh_failures
 * @property ?\Carbon\CarbonImmutable $metadata_claimed_until
 * @property ?string $metadata_claim_token
 * @property ?string $jwks
 * @property int $jwks_version
 * @property ?\Carbon\CarbonImmutable $jwks_fetched_at
 * @property ?\Carbon\CarbonImmutable $jwks_refetch_at
 * @property ?string $jwks_claim_token
 * @property int $jwks_refetch_suppressed
 * @property \Carbon\CarbonImmutable $created_at
 * @property \Carbon\CarbonImmutable $updated_at
 */
final class Connection extends SsoModel implements SsoConnection
{
    /** @var string The `sso.` setting that names the table. */
    protected const string TABLE = 'connections.table';

    /** @var list<string> The columns fixed when the connection is created. */
    private const array FIXED = ['tenant_id', 'protocol'];

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Stamped from the package's clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation. */
    protected $hidden = ['secrets', 'linking_organization_value'];

    /** @var array<string, mixed> The model's default attribute values. */
    protected $attributes = [
        'settings'              => '[]',
        'attribute_mapping'     => '[]',
        'enabled'               => false,
        'has_completed_sign_in' => false,
        'trust_version'         => 0,
        'linking_enabled'       => false,
        'linking_version'       => 0,
    ];

    /**
     * The connection's ULID.
     *
     * @return string
     */
    #[\Override]
    public function getConnectionId(): string
    {
        return $this->id;
    }

    /**
     * The opaque id of the tenant the connection belongs to.
     *
     * @return string
     */
    #[\Override]
    public function getTenantId(): string
    {
        return $this->tenant_id;
    }

    /**
     * The name of the driver the connection runs over.
     *
     * @return string
     */
    #[\Override]
    public function getProtocol(): string
    {
        return $this->protocol;
    }

    /**
     * The name administrators know the connection by.
     *
     * @return string
     */
    #[\Override]
    public function getDisplayName(): string
    {
        return $this->display_name;
    }

    /**
     * The settings as stored, with no secret among them.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function getSettings(): array
    {
        return $this->settings;
    }

    /**
     * The attribute mapping as stored.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function getAttributeMapping(): array
    {
        return $this->attribute_mapping;
    }

    /**
     * Whether the connection is enabled.
     *
     * @return bool
     */
    #[\Override]
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Whether a `sign_in` through the connection has ever been redeemed.
     *
     * @return bool
     */
    #[\Override]
    public function hasCompletedSignIn(): bool
    {
        return $this->has_completed_sign_in;
    }

    /**
     * The connection's settings for linking by a verified domain.
     *
     * @return array<string, bool|int|string|null>
     */
    #[\Override]
    public function getLinkingSettings(): array
    {
        return [
            'enabled'               => $this->linking_enabled,
            'issuer_class'          => $this->linking_issuer_class,
            'organization_claim'    => $this->linking_organization_claim,
            'organization_value'    => $this->linking_organization_value,
            'saml_attribute'        => $this->linking_saml_attribute,
            'saml_attribute_format' => $this->linking_saml_attribute_format,
            'acknowledged'          => $this->linking_acknowledged_at !== null,
            'version'               => $this->linking_version,
        ];
    }

    /**
     * The authentication context the connection accepts as evidence.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function getEvidencePolicy(): array
    {
        $policy = $this->evidence_policy;

        return is_array($policy) ? $policy : [];
    }

    /**
     * Key and stamp each new connection, and fix its tenant and protocol.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::identifiedAndStamped();

        self::updating(static function (self $connection): void {
            if ($connection->isDirty(self::FIXED)) {
                throw new \LogicException('A connection\'s tenant and protocol are fixed when it is created.');
            }
        });
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'settings'                  => 'array',
            'attribute_mapping'         => 'array',
            'enabled'                   => 'boolean',
            'has_completed_sign_in'     => 'boolean',
            'links_version'             => 'integer',
            'flows_version'             => 'integer',
            'trust_version'             => 'integer',
            'linking_enabled'           => 'boolean',
            'linking_version'           => 'integer',
            'evidence_policy'           => 'array',
            'linking_acknowledged_at'   => UtcDateTime::class,
            'metadata_version'          => 'integer',
            'metadata_fetched_at'       => UtcDateTime::class,
            'metadata_valid_until'      => UtcDateTime::class,
            'metadata_refresh_at'       => UtcDateTime::class,
            'metadata_refresh_failures' => 'integer',
            'metadata_claimed_until'    => UtcDateTime::class,
            'jwks_version'              => 'integer',
            'jwks_fetched_at'           => UtcDateTime::class,
            'jwks_refetch_at'           => UtcDateTime::class,
            'jwks_refetch_suppressed'   => 'integer',
            'created_at'                => UtcDateTime::class,
            'updated_at'                => UtcDateTime::class,
        ];
    }
}
