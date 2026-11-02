<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * The row an identity's linking changes queue on (SSO-8.8,
 * `Linking\IdentityLock`): whatever widens the identity's principals, reserves
 * a link for it, activates one or redeems a `link` for it writes it first. It
 * holds only the digest of the identity, when the identity first held an active
 * link by a verified domain (`domain_linked_at`, never cleared), and when the
 * row was first made, and it is never deleted, since another transaction may be
 * waiting on it.
 *
 * Its key is a lower-case ULID. The table comes from
 * `sso.identity_guards.table`, the connection from the storage connection.
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
    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'identity_guards.table';

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Indicates if the model should be timestamped: the package stamps it from its clock instead. */
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
