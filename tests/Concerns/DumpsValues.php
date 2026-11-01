<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Dumps a value every way a developer or a log might, so a test can assert that
 * none of them shows a protocol or provider value: PHP's `var_dump()`,
 * `print_r()` and `var_export()`, and Symfony's VarDumper, which Laravel's dump
 * helpers use and which also lists private properties.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait DumpsValues
{
    /**
     * Every dump of the value, by the name of what made it.
     *
     * @param  mixed  $value
     * @return array<string, string>
     */
    protected static function dumps(mixed $value): array
    {
        ob_start();
        var_dump($value); // phpcs:ignore SineMaculaLaravel.Debug.DisallowDebugStatements.Found -- the test asserts what it shows.
        $varDump = (string) ob_get_clean();

        return [
            'var_dump'   => $varDump,
            'print_r'    => print_r($value, true),
            'var_export' => var_export($value, true),
            'VarDumper'  => (string) (new CliDumper)->dump((new VarCloner)->cloneVar($value), true),
        ];
    }
}
