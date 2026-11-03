<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's tenant, an Eloquent model of its own `tenants`
 * table (SSO-4.2): a tenant tree in which a tenant names the root whose
 * enforcement it follows, or none when it is a root and its own rule applies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property ?string $enforcement_root_id
 *
 * @internal
 */
final class Tenant extends Model
{
    /** @var string The application's table. */
    public const string TABLE = 'tenants';

    /** @var bool Whether the key increments: it is a string. */
    public $incrementing = false;

    /** @var bool Whether the model is timestamped: the example needs no times. */
    public $timestamps = false;

    /** @var ?string The table the model is stored in. */
    protected $table = self::TABLE;

    /** @var string The key's type. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that may be filled. */
    protected $fillable = ['id', 'enforcement_root_id'];
}
