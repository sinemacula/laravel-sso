<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Models;

use SineMacula\Laravel\Sso\Models\SsoModel;

/**
 * A package model on the rate limits table, which lives on the counters'
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExampleCounter extends SsoModel
{
    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'rate_limits.table';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];
}
