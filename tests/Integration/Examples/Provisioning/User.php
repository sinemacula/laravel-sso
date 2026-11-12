<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Provisioning;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * The example application's user, on the package's storage connection so it
 * commits or rolls back with the link.
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

    /** @var bool The example needs no timestamps. */
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
