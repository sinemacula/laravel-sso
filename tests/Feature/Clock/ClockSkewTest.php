<?php

declare(strict_types = 1);

namespace Tests\Feature\Clock;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Clock\ClockSkew;
use Tests\TestCase;

/**
 * Feature tests for the configured clock skew.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClockSkew::class)]
final class ClockSkewTest extends TestCase
{
    /** @var string The message a malformed skew fails closed with. */
    private const string MESSAGE = 'sso.clock.skew_seconds must be an integer from 0 to 300.';

    /**
     * The shipped configuration allows 60 seconds.
     *
     * @return void
     */
    public function testTheShippedDefaultIsSixtySeconds(): void
    {
        self::assertSame(60, ClockSkew::seconds());
    }

    /**
     * An unset skew is 60 seconds.
     *
     * @return void
     */
    public function testTheDefaultAppliesWhenTheSkewIsNotSet(): void
    {
        config()->set('sso.clock', []);

        self::assertSame(60, ClockSkew::seconds());

        config()->set('sso', []);

        self::assertSame(60, ClockSkew::seconds());
    }

    /**
     * Rows of `[value, seconds]`: the integers and digit strings accepted.
     *
     * @return iterable<string, array{0: int|string, 1: int}>
     */
    public static function provideAcceptedValues(): iterable
    {
        yield from [
            'none'                    => [0, 0],
            'one second'              => [1, 1],
            'the default'             => [60, 60],
            'the ceiling'             => [300, 300],
            'none as a string'        => ['0', 0],
            'a minute as a string'    => ['60', 60],
            'two minutes, a string'   => ['120', 120],
            'the ceiling as a string' => ['300', 300],
        ];
    }

    /**
     * Each accepted value is the skew, in seconds.
     *
     * @param  int|string  $value
     * @param  int  $seconds
     * @return void
     */
    #[DataProvider('provideAcceptedValues')]
    public function testAcceptsAnIntegerFromZeroToThreeHundred(int|string $value, int $seconds): void
    {
        config()->set('sso.clock.skew_seconds', $value);

        self::assertSame($seconds, ClockSkew::seconds());
    }

    /**
     * Rows of `[value]`: values that are not an integer from 0 to 300.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield from [
            'below none'         => [-1],
            'past the ceiling'   => [301],
            'below, as a string' => ['-1'],
            'past, as a string'  => ['301'],
            'a decimal string'   => ['1.5'],
            'a float'            => [1.5],
            'a whole float'      => [60.0],
            'null'               => [null],
            'an empty string'    => [''],
            'the word null'      => ['null'],
            'padded'             => ['060'],
            'signed'             => ['+60'],
            'with leading space' => [' 60'],
            'a boolean'          => [true],
            'a word'             => ['sixty'],
            'an empty array'     => [[]],
            'an array'           => [[60]],
        ];
    }

    /**
     * A value outside 0 to 300 fails closed, naming the key and never the
     * value.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesAnythingElse(mixed $value): void
    {
        config()->set('sso.clock.skew_seconds', $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MESSAGE);

        ClockSkew::seconds();
    }

    /**
     * The skew is read on each call.
     *
     * @return void
     */
    public function testIsReadOnEachCall(): void
    {
        config()->set('sso.clock.skew_seconds', 30);

        self::assertSame(30, ClockSkew::seconds());

        config()->set('sso.clock.skew_seconds', '120');

        self::assertSame(120, ClockSkew::seconds());
    }

    /**
     * `ClockSkew` is a utility container, not to be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ClockSkew::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ClockSkew::class, $instance);
    }
}
