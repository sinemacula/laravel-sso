<?php

declare(strict_types = 1);

namespace Tests\Unit\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Connections\SettingViolation;

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

    /**
     * A URL's scheme is read whatever its case.
     *
     * @return void
     */
    public function testReadsAUrlsSchemeWhateverItsCase(): void
    {
        self::assertNull(SettingRules::url('HTTPS://idp.example.com/sso'));
        self::assertSame(ViolationCode::NOT_HTTPS, SettingRules::url('HTTP://idp.example.com/sso'));
    }

    /**
     * A path names the key under its parent up to the longest setting a
     * violation holds; an empty, unprintable or longer one names the parent.
     *
     * @return void
     */
    public function testNamesAPathUpToTheLongestSetting(): void
    {
        $longest = str_repeat('a', SettingViolation::MAX_SETTING_LENGTH);

        self::assertSame($longest, SettingRules::path(null, $longest));
        self::assertSame('settings', SettingRules::path(null, $longest . 'a'));
        self::assertSame('scopes.' . substr($longest, 7), SettingRules::path('scopes', substr($longest, 7)));
        self::assertSame('scopes', SettingRules::path('scopes', substr($longest, 6)));
        self::assertSame('scopes.0', SettingRules::path('scopes', 0));
        self::assertSame('scopes', SettingRules::path('scopes', ''));
        self::assertSame('scopes', SettingRules::path('scopes', "a\0b"));
    }

    /**
     * A value is printable when it is UTF-8 with no control character.
     *
     * @return void
     */
    public function testAValueIsPrintableWithoutAControlCharacter(): void
    {
        self::assertTrue(SettingRules::isPrintable('Acme Ltd'));
        self::assertFalse(SettingRules::isPrintable("Acme\nLtd"));
        self::assertFalse(SettingRules::isPrintable("\xC3\x28"));
    }
}
