<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\StartingAFlow;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's user, keyed by a string and never stored.
 *
 * @method int|string getKey() The key, a string here, an integer in many applications.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class User extends Model
{
    /** @var bool Whether the key increments: it is a string. */
    public $incrementing = false;

    /** @var string The key's type. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that may be filled. */
    protected $fillable = ['id'];
}
