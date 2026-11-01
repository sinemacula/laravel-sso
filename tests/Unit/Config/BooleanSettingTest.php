<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Config\BooleanSetting;

/**
 * Unit tests for the switch reader every settings class shares: the default,
 * the forms it accepts, and the message it fails closed with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BooleanSetting::class)]
final class BooleanSettingTest extends TestCase
{
    /** @var string The key the tests read. */
    private const string KEY = 'sso.features.example';

    /**
     * A switch that is not configured takes the default, which the caller
     * chooses.
     *
     * @return void
     */
    public function testTheDefaultAppliesWhenTheKeyIsNotSet(): void
    {
        self::assertFalse(BooleanSetting::read(new Repository, self::KEY, false));
        self::assertTrue(BooleanSetting::read(new Repository, self::KEY, true));
    }

    /**
     * Rows of `[value, what it reads as]`: booleans, and the integers and
     * strings `env()` and a deploy pipeline give for one.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideAcceptedValues(): iterable
    {
        yield from [
            'true'             => [true, true],
            'false'            => [false, false],
            'one'              => [1, true],
            'zero'             => [0, false],
            'one as a string'  => ['1', true],
            'zero as a string' => ['0', false],
            'the word true'    => ['true', true],
            'the word false'   => ['false', false],
        ];
    }

    /**
     * Each accepted value reads as the boolean it names.
     *
     * @param  mixed  $value
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideAcceptedValues')]
    public function testReadsBooleansAndTheirForms(mixed $value, bool $expected): void
    {
        $config = new Repository([]);

        $config->set(self::KEY, $value);

        self::assertSame($expected, BooleanSetting::read($config, self::KEY, !$expected));
        self::assertSame($expected, BooleanSetting::parse($value));
    }

    /**
     * Rows of `[value]`: values that name no boolean.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield from [
            'null'            => [null],
            'two'             => [2],
            'minus one'       => [-1],
            'a float'         => [1.0],
            'an empty string' => [''],
            'yes'             => ['yes'],
            'upper-case TRUE' => ['TRUE'],
            'padded one'      => [' 1'],
            'an array'        => [[true]],
            'an object'       => [new \stdClass],
        ];
    }

    /**
     * A value that names no boolean fails closed, naming the key, rather than
     * guessing whether the feature was meant to be on.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesAValueThatNamesNoBoolean(mixed $value): void
    {
        self::assertNull(BooleanSetting::parse($value));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('sso.features.example must be true or false.');

        BooleanSetting::isOn(self::KEY, $value);
    }

    /**
     * `BooleanSetting` is a utility container, not to be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(BooleanSetting::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(BooleanSetting::class, $instance);
    }
}
