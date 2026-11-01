<?php

declare(strict_types = 1);

namespace Tests\Unit\Flows;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\RequestReference;

/**
 * Unit tests for a request's public reference: 32 random base64url characters,
 * under the 40 the log sanitiser redacts, read back only in that form, compared
 * exactly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestReference::class)]
final class RequestReferenceTest extends TestCase
{
    /**
     * A generated reference is 32 base64url characters, under 40, and new each
     * time.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testGeneratesARandomReference(): void
    {
        $one = RequestReference::generate();
        $two = RequestReference::generate();

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{32}$/', $one->value);
        self::assertSame(32, RequestReference::LENGTH);
        self::assertLessThan(40, strlen($one->value));
        self::assertNotSame($one->value, $two->value);
        self::assertFalse($one->is($two));
    }

    /**
     * A reference reads back from exactly its form, and shows as itself.
     *
     * @return void
     */
    public function testReadsBackAReference(): void
    {
        $value     = str_repeat('aZ09_-', 5) . 'ab';
        $reference = RequestReference::fromString($value);

        self::assertSame($value, $reference->value);
        self::assertSame($value, (string) $reference);
        self::assertSame('"' . $value . '"', json_encode($reference));
        self::assertTrue($reference->is(RequestReference::fromString($value)));
        self::assertFalse($reference->is(RequestReference::fromString(strtoupper($value))));
    }

    /**
     * Anything but exactly 32 base64url characters is not a reference.
     *
     * @return void
     */
    public function testRefusesWhatIsNotAReference(): void
    {
        foreach ([str_repeat('a', 31), str_repeat('a', 33), str_repeat('a', 31) . '+', str_repeat('a', 31) . '=', str_repeat('a', 32) . "\n", ''] as $value) {
            self::assertFalse(RequestReference::isWellFormed($value), $value);
        }

        self::assertTrue(RequestReference::isWellFormed(str_repeat('a', 32)));

        $this->expectExceptionObject(new \InvalidArgumentException('A request reference is 32 base64url characters.'));

        RequestReference::fromString(str_repeat('a', 31));
    }
}
