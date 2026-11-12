<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's tenant membership, stored on the package's storage
 * connection.
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
