<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Provisioning;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * The example application's user, an Eloquent model of its own `users` table
 * (SSO-8.6): the person its provisioning listener creates for a sign-in that
 * resolved to nobody, named to the package by its morph class and key. Its
 * table lives on the default connection, which is also the package's storage
 * connection here, so the user, their membership and the link commit or roll
 * back as one.
 *
 * @method int|string getKey() The key, an integer here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $name
 *
 * @internal
 */
final class User extends Model
{
    /** @var string The application's table. */
    public const string TABLE = 'users';

    /** @var bool Whether the model is timestamped: the example needs no times. */
    public $timestamps = false;

    /** @var ?string The table the model is stored in. */
    protected $table = self::TABLE;

    /** @var list<string> The attributes that may be filled. */
    protected $fillable = ['name'];

    /**
     * The user's memberships of tenants.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany<\Tests\Integration\Examples\Provisioning\Membership, $this>
     */
    public function memberships(): HasMany
    {
        return $this->hasMany(Membership::class);
    }
}
