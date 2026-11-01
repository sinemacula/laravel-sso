<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Models;

use SineMacula\Laravel\Sso\Models\SsoModel;

/**
 * A package model on the single-use table, as a shipped model names its table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property string $namespace
 */
final class ExampleKey extends SsoModel
{
    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'single_use.table';

    /** @var bool Indicates if the model should be timestamped. */
    public $timestamps = false;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
