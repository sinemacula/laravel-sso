<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\AttributeMapping;
use SineMacula\Laravel\Sso\Connections\MappingLimits;
use Tests\TestCase;

/**
 * Feature tests for what an attribute mapping may carry (SSO-2.10): the caps'
 * defaults, the digit strings `env()` gives, each range failing closed naming
 * its key, the custom keys the application declares (none by default, at most
 * 100 distinct well-formed keys, none standard or reserved), and a read on each
 * call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MappingLimits::class)]
#[CoversClass(AttributeMapping::class)]
final class MappingLimitsTest extends TestCase
{
    /** @var string What a malformed declaration of custom keys fails with. */
    private const string MALFORMED_CUSTOM = 'sso.mapping.custom_attributes must be a list of at most 100 distinct custom keys, each a lower-case letter then up to 63 '
        . 'lower-case letters, digits or underscores, and none a standard or reserved key.';

    /**
     * The shipped configuration and an absent one both give the defaults: no
     * custom key is declared.
     *
     * @return void
     */
    public function testHasProductionSafeDefaults(): void
    {
        $limits = $this->limits();

        self::assertSame(1024, $limits->maxValueLength());
        self::assertSame(100, $limits->maxValues());
        self::assertSame([], $limits->customAttributes());

        config()->set('sso.mapping', []);

        self::assertSame(MappingLimits::DEFAULT_MAX_VALUE_LENGTH, $limits->maxValueLength());
        self::assertSame(MappingLimits::DEFAULT_MAX_VALUES, $limits->maxValues());
        self::assertSame([], $limits->customAttributes());
        self::assertSame(100, MappingLimits::MAX_CUSTOM_ATTRIBUTES);
    }

    /**
     * The digit string `env()` gives is read as its integer, and each setting
     * is read on each call.
     *
     * @return void
     */
    public function testReadsEachSettingOnEachCall(): void
    {
        $limits = $this->limits();

        config()->set('sso.mapping', ['max_value_length' => '64', 'max_values' => '10000', 'custom_attributes' => ['department']]);

        self::assertSame(64, $limits->maxValueLength());
        self::assertSame(10000, $limits->maxValues());
        self::assertSame(['department'], $limits->customAttributes());

        config()->set('sso.mapping', ['max_value_length' => 65535, 'max_values' => 1, 'custom_attributes' => ['employee_number', 'cost_centre']]);

        self::assertSame(65535, $limits->maxValueLength());
        self::assertSame(1, $limits->maxValues());
        self::assertSame(['employee_number', 'cost_centre'], $limits->customAttributes());
    }

    /**
     * Up to 100 declared keys, the longest of 64 characters, are kept in the
     * order given.
     *
     * @return void
     */
    public function testDeclaresUpToTheCapOfWellFormedKeys(): void
    {
        $keys = array_map(static fn (int $index): string => 'key_' . $index, range(1, 99));
        $keys = [...$keys, 'a' . str_repeat('b', 63)];

        config()->set('sso.mapping.custom_attributes', $keys);

        self::assertSame($keys, $this->limits()->customAttributes());
    }

    /**
     * Rows of `[key, value, message]`: a malformed setting and the problem it
     * fails with.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        $length = 'sso.mapping.max_value_length must be an integer from 64 to 65535.';
        $values = 'sso.mapping.max_values must be an integer from 1 to 10000.';
        $custom = self::MALFORMED_CUSTOM;

        yield from [
            'a value length under its range'  => ['max_value_length', 63, $length],
            'a value length over its range'   => ['max_value_length', 65536, $length],
            'a value length in words'         => ['max_value_length', 'long', $length],
            'a padded value length'           => ['max_value_length', ' 128', $length],
            'a fractional value length'       => ['max_value_length', 128.5, $length],
            'no values'                       => ['max_values', 0, $values],
            'too many values'                 => ['max_values', 10001, $values],
            'a signed number of values'       => ['max_values', '+10', $values],
            'a null number of values'         => ['max_values', null, $values],
            'custom keys as a string'         => ['custom_attributes', 'department', $custom],
            'custom keys as null'             => ['custom_attributes', null, $custom],
            'custom keys as a map'            => ['custom_attributes', ['a' => 'department'], $custom],
            'custom keys with a gap'          => ['custom_attributes', [1 => 'department'], $custom],
            'a custom key that is no string'  => ['custom_attributes', ['department', 7], $custom],
            'an upper-case custom key'        => ['custom_attributes', ['Department'], $custom],
            'a custom key with a digit first' => ['custom_attributes', ['1department'], $custom],
            'a custom key with a hyphen'      => ['custom_attributes', ['cost-centre'], $custom],
            'a custom key of 65 characters'   => ['custom_attributes', ['a' . str_repeat('b', 64)], $custom],
            'an empty custom key'             => ['custom_attributes', [''], $custom],
            'a standard key declared'         => ['custom_attributes', ['groups'], $custom],
            'a reserved key declared'         => ['custom_attributes', ['tenant_id'], $custom],
            'a custom key declared twice'     => ['custom_attributes', ['department', 'department'], $custom],
            'more than 100 custom keys'       => ['custom_attributes', array_map(static fn (int $index): string => 'key_' . $index, range(1, 101)), $custom],
        ];
    }

    /**
     * A malformed setting fails closed, naming its key and what it must be.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testAMalformedSettingFailsClosed(string $key, mixed $value, string $message): void
    {
        config()->set('sso.mapping.' . $key, $value);

        $read = match ($key) {
            'max_value_length' => $this->limits()->maxValueLength(...),
            'max_values'       => $this->limits()->maxValues(...),
            default            => $this->limits()->customAttributes(...),
        };

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $read();
    }

    /**
     * The caps, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Connections\MappingLimits
     */
    private function limits(): MappingLimits
    {
        $limits = $this->app?->make(MappingLimits::class);

        self::assertInstanceOf(MappingLimits::class, $limits);

        return $limits;
    }
}
