<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\MappingLimits;
use Tests\TestCase;

/**
 * Feature tests for the caps on what an attribute mapping carries (SSO-2.10):
 * their defaults, the digit strings `env()` gives, each range failing closed
 * naming its key, and a read on each call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MappingLimits::class)]
final class MappingLimitsTest extends TestCase
{
    /**
     * The shipped configuration and an absent one both give the defaults.
     *
     * @return void
     */
    public function testHasProductionSafeDefaults(): void
    {
        $limits = $this->limits();

        self::assertSame(1024, $limits->maxValueLength());
        self::assertSame(100, $limits->maxValues());
        self::assertSame(20, $limits->maxCustomAttributes());

        config()->set('sso.mapping', []);

        self::assertSame(MappingLimits::DEFAULT_MAX_VALUE_LENGTH, $limits->maxValueLength());
        self::assertSame(MappingLimits::DEFAULT_MAX_VALUES, $limits->maxValues());
        self::assertSame(MappingLimits::DEFAULT_MAX_CUSTOM_ATTRIBUTES, $limits->maxCustomAttributes());
    }

    /**
     * The digit string `env()` gives is read as its integer, and each cap is
     * read on each call.
     *
     * @return void
     */
    public function testReadsDigitStringsOnEachCall(): void
    {
        $limits = $this->limits();

        config()->set('sso.mapping', ['max_value_length' => '64', 'max_values' => '10000', 'max_custom_attributes' => '0']);

        self::assertSame(64, $limits->maxValueLength());
        self::assertSame(10000, $limits->maxValues());
        self::assertSame(0, $limits->maxCustomAttributes());

        config()->set('sso.mapping', ['max_value_length' => 65535, 'max_values' => 1, 'max_custom_attributes' => 100]);

        self::assertSame(65535, $limits->maxValueLength());
        self::assertSame(1, $limits->maxValues());
        self::assertSame(100, $limits->maxCustomAttributes());
    }

    /**
     * Rows of `[key, value, message]`: a malformed cap and the problem it fails
     * with.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedCaps(): iterable
    {
        $length = 'sso.mapping.max_value_length must be an integer from 64 to 65535.';
        $values = 'sso.mapping.max_values must be an integer from 1 to 10000.';
        $custom = 'sso.mapping.max_custom_attributes must be an integer from 0 to 100.';

        yield from [
            'a value length under its range'   => ['max_value_length', 63, $length],
            'a value length over its range'    => ['max_value_length', 65536, $length],
            'a value length in words'          => ['max_value_length', 'long', $length],
            'a padded value length'            => ['max_value_length', ' 128', $length],
            'a fractional value length'        => ['max_value_length', 128.5, $length],
            'no values'                        => ['max_values', 0, $values],
            'too many values'                  => ['max_values', 10001, $values],
            'a signed number of values'        => ['max_values', '+10', $values],
            'a null number of values'          => ['max_values', null, $values],
            'a negative custom count'          => ['max_custom_attributes', -1, $custom],
            'too many custom attributes'       => ['max_custom_attributes', 101, $custom],
            'an exponent of custom attributes' => ['max_custom_attributes', '1e1', $custom],
            'a boolean custom count'           => ['max_custom_attributes', true, $custom],
        ];
    }

    /**
     * A malformed cap fails closed, naming its key and range.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedCaps')]
    public function testAMalformedCapFailsClosed(string $key, mixed $value, string $message): void
    {
        config()->set('sso.mapping.' . $key, $value);

        $read = match ($key) {
            'max_value_length' => $this->limits()->maxValueLength(...),
            'max_values'       => $this->limits()->maxValues(...),
            default            => $this->limits()->maxCustomAttributes(...),
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
