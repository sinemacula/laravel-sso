<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Provisioning;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's membership of a tenant, an Eloquent model of its
 * own `memberships` table (SSO-8.6): the user and the tenant they are a member
 * of, created with the user by the provisioning listener, on the default
 * connection, which is also the package's storage connection here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $user_id
 * @property string $tenant_id
 *
 * @internal
 */
final class Membership extends Model
{
    /** @var string The application's table. */
    public const string TABLE = 'memberships';

    /** @var bool Whether the model is timestamped: the example needs no times. */
    public $timestamps = false;

    /** @var ?string The table the model is stored in. */
    protected $table = self::TABLE;

    /** @var list<string> The attributes that may be filled. */
    protected $fillable = ['tenant_id'];
}
