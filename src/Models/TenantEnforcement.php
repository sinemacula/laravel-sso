<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Enforcement\TenantHash;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One tenant's enforcement (SSO-4.1, SSO-4.6): whether sessions active in it
 * must be established through one of its own connections, which connections
 * satisfy it (their ids, a JSON list), and the version that changes with every
 * change, a fresh lower-case ULID each time.
 *
 * The tenant is the application's opaque string id, fixed once the row exists.
 * One row per tenant is kept by `tenant_hash`, the lower-case hex SHA-256 of
 * the id, set from it as the row is created, under a unique index, so a
 * collation that counts `acme` and `Acme` as equal cannot merge two tenants; a
 * query by the hash still checks the row's `tenant_id` byte for byte.
 *
 * Its key is a lower-case ULID and its timestamps come from the package's clock
 * (see `SsoModel`). The table comes from `sso.enforcement.table`, the
 * connection from the storage connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $tenant_id
 * @property string $tenant_hash
 * @property bool $enabled
 * @property list<string> $connection_ids
 * @property string $version
 * @property \Carbon\CarbonImmutable $changed_at
 * @property \Carbon\CarbonImmutable $created_at
 * @property \Carbon\CarbonImmutable $updated_at
 */
final class TenantEnforcement extends SsoModel
{
    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'enforcement.table';

    /** @var list<string> The columns fixed when the row is created. */
    private const array FIXED = ['tenant_id', 'tenant_hash'];

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Indicates if the model should be timestamped: the package stamps it from its clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var array<string, mixed> The model's default attribute values: a new row is off, with no satisfying connection. */
    protected $attributes = [
        'enabled'        => false,
        'connection_ids' => '[]',
    ];

    /**
     * Key and stamp each new row, set its tenant hash from its tenant id, and
     * refuse a change to either once it exists.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::identifiedAndStamped();

        self::creating(static function (self $enforcement): void {
            $enforcement->tenant_hash = TenantHash::of($enforcement->tenant_id);
        });

        self::updating(static function (self $enforcement): void {
            if ($enforcement->isDirty(self::FIXED)) {
                throw new \LogicException('A tenant\'s enforcement belongs to the tenant it was created for.');
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
            'enabled'        => 'boolean',
            'connection_ids' => 'array',
            'changed_at'     => UtcDateTime::class,
            'created_at'     => UtcDateTime::class,
            'updated_at'     => UtcDateTime::class,
        ];
    }
}
