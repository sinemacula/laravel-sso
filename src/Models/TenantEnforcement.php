<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Enforcement\TenantHash;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One tenant's enforcement rule, unique by `tenant_hash`.
 *
 * A row with no version is the unconfigured guard row `EnforcementLock`
 * inserts, and reads exactly as no row.
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
 * @property ?string $version
 * @property ?\Carbon\CarbonImmutable $changed_at
 * @property \Carbon\CarbonImmutable $created_at
 * @property \Carbon\CarbonImmutable $updated_at
 */
final class TenantEnforcement extends SsoModel
{
    /** @var string The `sso.` setting that names the table. */
    protected const string TABLE = 'enforcement.table';

    /** @var list<string> The columns fixed when the row is created. */
    private const array FIXED = ['tenant_id', 'tenant_hash'];

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Stamped from the package's clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var array<string, mixed> A new row is off, with no connection. */
    protected $attributes = [
        'enabled'        => false,
        'connection_ids' => '[]',
    ];

    /**
     * Key, stamp and hash each new row, and fix its tenant once it exists.
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
