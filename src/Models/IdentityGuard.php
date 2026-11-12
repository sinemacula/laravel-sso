<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * The row an identity's linking changes lock first (`Linking\IdentityLock`).
 *
 * Never deleted, since another transaction may be waiting on it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property string $id
 * @property string $identity_hash
 * @property ?\Carbon\CarbonImmutable $domain_linked_at
 * @property \Carbon\CarbonImmutable $created_at
 */
final class IdentityGuard extends SsoModel
{
    /** @var string The `sso.` setting that names the table. */
    protected const string TABLE = 'identity_guards.table';

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Stamped from the package's clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['domain_linked_at' => UtcDateTime::class, 'created_at' => UtcDateTime::class];
    }
}
