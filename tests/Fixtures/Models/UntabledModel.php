<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Models;

use SineMacula\Laravel\Sso\Models\SsoModel;

/**
 * A package model that names no table, as a model must not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UntabledModel extends SsoModel
{
    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];
}
