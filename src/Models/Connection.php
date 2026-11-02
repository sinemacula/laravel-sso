<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One connection: a tenant's trust in one identity provider over one protocol
 * (SSO-2.1). It holds its tenant (an opaque string id) and its protocol, both
 * fixed at creation; its display name; its settings, by name, with no secret
 * among them; its secrets, a JSON object of each secret's name and its
 * ciphertext from `Contracts\SecretEncrypter`, so a read can say which are set
 * without decrypting one, never read back by a helper (SSO-2.5); its attribute
 * mapping (SSO-2.10); whether it is enabled; whether a `sign_in` through it has
 * ever been redeemed (SSO-4.3), which only the redemption sets; its links
 * version, which every link created through it raises under its lock
 * (`Links\LinkStore::create()`), so a link's insert also writes this row; and
 * its flows version, which every authorisation request stored and every handoff
 * code issued through it raises under its lock, so either insert also writes
 * this row (`Connections\InFlightVoider`); its trust version, which every
 * change that voids what is in flight through it, and enabling it, raises under
 * its lock; its metadata refresh state: the metadata version every refresh that
 * writes raises, the last validated fetch, the earliest `validUntil` it
 * applied, when the next refresh is due, how many failed in a row, and until
 * when a refresh in progress holds its claim and the random token that claim
 * was made with, which only its owner's write matches (SSO-2.8), whether of a
 * SAML connection's metadata or an OIDC connection's discovery document and
 * JWKS; and an OIDC connection's JWKS (SSO-7.3): the public keys the package
 * admitted, the version every write of them raises, their last validated fetch,
 * until when no unknown-`kid` refetch may start, and the random token of the
 * refetch in progress.
 *
 * Its key is a lower-case ULID, the `{connection}` of its endpoints, and its
 * timestamps come from the package's clock (see `SsoModel`). Changing its
 * tenant or protocol once it exists throws a `LogicException`: the management
 * helpers refuse such a change as a value before it reaches the model.
 *
 * The table comes from `sso.connections.table`, the connection from the storage
 * connection. Only the class name is public; its columns and behaviour belong
 * to the management helpers and the protocol drivers, which read it through
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
    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'connections.table';

    /** @var list<string> The columns fixed when the connection is created (SSO-2.1). */
    private const array FIXED = ['tenant_id', 'protocol'];

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Indicates if the model should be timestamped: the package stamps it from its clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation: the encrypted secrets. */
    protected $hidden = ['secrets'];

    /** @var array<string, mixed> The model's default attribute values: disabled, no sign-in completed, no settings or mapping, trust version 0. */
    protected $attributes = [
        'settings'              => '[]',
        'attribute_mapping'     => '[]',
        'enabled'               => false,
        'has_completed_sign_in' => false,
        'trust_version'         => 0,
    ];

    /**
     * The connection's id.
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
     * Key and stamp each new connection, and refuse a change to its tenant or
     * protocol once it exists.
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
