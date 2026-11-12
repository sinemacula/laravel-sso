<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's session, stored on the package's storage
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $identity_type
 * @property string $identity_id
 * @property ?string $sso_link_id
 * @property bool $sso_domain_link
 * @property ?string $renewed_link_id
 *
 * @internal
 */
final class UserSession extends Model
{
    /** @var string The application's table. */
    public const string TABLE = 'user_sessions';

    /** @var bool Whether the key increments: it is a string. */
    public $incrementing = false;

    /** @var bool Whether the model is timestamped: the example needs no times. */
    public $timestamps = false;

    /** @var ?string The table the model is stored in. */
    protected $table = self::TABLE;

    /** @var string The key's type. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that may be filled. */
    protected $fillable = ['id', 'identity_type', 'identity_id', 'sso_link_id', 'sso_domain_link', 'renewed_link_id'];

    /**
     * The attributes cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['sso_domain_link' => 'boolean'];
    }
}
