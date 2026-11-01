<?php

declare(strict_types = 1);

namespace Tests\Unit\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\SettingRules;

/**
 * Unit tests for how a stored value is compared with the one given: a map
 * whatever its key order, nested maps included, and a list in order, with types
 * compared strictly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SettingRules::class)]
final class SettingRulesTest extends TestCase
{
    /**
     * Pairs of values, and whether they are the same.
     *
     * @return iterable<string, array{0: mixed, 1: mixed, 2: bool}>
     */
    public static function provideValues(): iterable
    {
        yield 'equal scalars' => ['login', 'login', true];
        yield 'scalars of another type' => [1, '1', false];
        yield 'a map in another key order' => [['prompt' => 'login', 'login_hint' => 'x'], ['login_hint' => 'x', 'prompt' => 'login'], true];
        yield 'a nested map in another key order' => [['a' => ['y' => 1, 'x' => 2]], ['a' => ['x' => 2, 'y' => 1]], true];
        yield 'a map within a list in another key order' => [[['y' => 1, 'x' => 2]], [['x' => 2, 'y' => 1]], true];
        yield 'a map with another value' => [['prompt' => 'login'], ['prompt' => 'none'], false];
        yield 'a map with another key' => [['prompt' => 'login'], ['display' => 'login'], false];
        yield 'a list in another order' => [['openid', 'email'], ['email', 'openid'], false];
        yield 'a list with a value of another type' => [['1'], [1], false];
        yield 'a map of numeric keys in another order' => [[2 => 'b', 1 => 'a'], [1 => 'a', 2 => 'b'], true];
    }

    /**
     * Maps are compared whatever their key order, lists in order, and every
     * value strictly.
     *
     * @param  mixed  $one
     * @param  mixed  $other
     * @param  bool  $same
     * @return void
     */
    #[DataProvider('provideValues')]
    public function testComparesMapsWhateverTheirKeyOrder(mixed $one, mixed $other, bool $same): void
    {
        self::assertSame($same, SettingRules::isSame($one, $other));
        self::assertSame($same, SettingRules::isSame($other, $one));
    }
}
