<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's session, an Eloquent model of its own
 * `user_sessions` table (SSO-8.8): the identity it is for, the link it was
 * established through (none for a password session), whether that link had
 * verified domain provenance when the session was admitted, and the link a
 * reauthentication last renewed it through, if any.
 *
 * Its table lives on the package's storage connection, where the application's
 * sessions read it, so a locking read of it takes part in a redemption's
 * transaction.
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
