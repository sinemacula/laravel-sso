<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's membership of a tenant, an Eloquent model of its
 * own `memberships` table (SSO-8.5): the identity, by its type and id, and the
 * tenant it is a member of. Its link eligibility reads it, locked, on the
 * package's storage connection, so the read takes part in a redemption's
 * transaction; its table lives there too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $identity_type
 * @property string $identity_id
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
    protected $fillable = ['identity_type', 'identity_id', 'tenant_id'];
}
