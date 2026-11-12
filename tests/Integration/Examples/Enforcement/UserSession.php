<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's session, recording how it was established and the
 * enforcement version it was last judged against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $user_type
 * @property string $user_id
 * @property string $tenant_id
 * @property ?string $sso_connection_id
 * @property ?string $sso_link_id
 * @property ?string $enforcement_version
 * @property ?string $revoked_at
 * @property ?string $revoked_reason
 *
 * @internal
 */
final class UserSession extends Model
{
    /** @var string The application's table. */
    public const string TABLE = 'sessions';

    /** @var bool Whether the key increments: it is a string. */
    public $incrementing = false;

    /** @var bool Whether the model is timestamped: the example needs no times. */
    public $timestamps = false;

    /** @var ?string The table the model is stored in. */
    protected $table = self::TABLE;

    /** @var string The key's type. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that may be filled. */
    protected $fillable = ['id', 'user_type', 'user_id', 'tenant_id', 'sso_connection_id', 'sso_link_id', 'enforcement_version'];
}
