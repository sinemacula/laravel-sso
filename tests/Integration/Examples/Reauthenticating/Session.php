<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Reauthenticating;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's session, stored on the package's storage connection
 * so a locking read joins a redemption's transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $identity_type
 * @property string $identity_id
 * @property string $application
 * @property string $connection_id
 * @property ?string $sso_link_id
 * @property ?\Carbon\CarbonImmutable $authenticated_at
 * @property ?\Carbon\CarbonImmutable $revoked_at
 *
 * @internal
 */
final class Session extends Model
{
    /** @var string The application's table. */
    public const string TABLE = 'app_sessions';

    /** @var bool Whether the key increments: it is the session's own id. */
    public $incrementing = false;

    /** @var bool Whether the model is timestamped: the example needs no times. */
    public $timestamps = false;

    /** @var ?string The table the model is stored in. */
    protected $table = self::TABLE;

    /** @var string The key's type. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that may be filled. */
    protected $fillable = ['id', 'identity_type', 'identity_id', 'application', 'connection_id', 'sso_link_id', 'authenticated_at', 'revoked_at'];

    /**
     * The attributes cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['authenticated_at' => 'immutable_datetime', 'revoked_at' => 'immutable_datetime'];
    }
}
