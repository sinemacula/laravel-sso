<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's user, an Eloquent model identified by a string key
 * (SSO-8.3, SSO-8.4): the person who links an identity provider from their
 * account screen, named to the package by its morph class and key.
 *
 * It is never stored: an example makes one in memory, as the application's
 * authentication hands its own user to an account screen.
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
