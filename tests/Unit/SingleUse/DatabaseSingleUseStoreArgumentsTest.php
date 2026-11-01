<?php

declare(strict_types = 1);

namespace Tests\Unit\SingleUse;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\SingleUse\DatabaseSingleUseStore;
use Tests\Fixtures\FixedClock;

/**
 * Unit tests for the arguments the default single-use store refuses: a
 * malformed namespace, an empty key and an expiry that is not after now are
 * each an `InvalidArgumentException`, thrown before any statement (there is no
 * application here, so a statement would fail otherwise), and no message names
 * the key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseSingleUseStore::class)]
final class DatabaseSingleUseStoreArgumentsTest extends TestCase
{
    /** @var string A key that must never appear in a message. */
    private const string KEY = 'handoff-code-that-must-stay-secret';

    /** @var string The namespace message. */
    private const string NAMESPACE_MESSAGE = 'A single-use namespace must be 1 to 64 characters of lower case letters, digits, `_`, `.`, `:` and `-`.';

    /**
     * Namespaces the contract does not allow.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedNamespaces(): iterable
    {
        yield from [
            'empty'                 => [''],
            '65 characters'         => [str_repeat('a', 65)],
            'upper case'            => ['Handoff_code'],
            'a space'               => ['handoff code'],
            'a slash'               => ['handoff/code'],
            'a trailing newline'    => ["handoff_code\n"],
            'a leading newline'     => ["\nhandoff_code"],
            'a non-ASCII letter'    => ['handoff_cödé'],
            'a null byte'           => ["handoff\0code"],
            'the key in a bad form' => ['Handoff ' . self::KEY],
        ];
    }

    /**
     * A malformed namespace is refused before anything else, and its message
     * names neither the namespace nor the key.
     *
     * @param  string  $namespace
     * @return void
     */
    #[DataProvider('provideMalformedNamespaces')]
    public function testRefusesAMalformedNamespace(string $namespace): void
    {
        $exception = $this->refusal($namespace, self::KEY, $this->clock()->now()->addMinute());

        self::assertSame(self::NAMESPACE_MESSAGE, $exception->getMessage());
        self::assertStringNotContainsString(self::KEY, $exception->getMessage());
    }

    /**
     * An empty key is refused.
     *
     * @return void
     */
    public function testRefusesAnEmptyKey(): void
    {
        $exception = $this->refusal('handoff_code', '', $this->clock()->now()->addMinute());

        self::assertSame('A single-use key must not be empty.', $exception->getMessage());
    }

    /**
     * Expiries, in seconds from now, that are not after now.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideExpiriesNotAfterNow(): iterable
    {
        yield from [
            'now'          => [0],
            'a second ago' => [-1],
            'an hour ago'  => [-3600],
        ];
    }

    /**
     * An expiry equal to now, or before it, is refused, and the message does
     * not name the key.
     *
     * @param  int  $seconds
     * @return void
     */
    #[DataProvider('provideExpiriesNotAfterNow')]
    public function testRefusesAnExpiryThatIsNotAfterNow(int $seconds): void
    {
        $exception = $this->refusal('handoff_code', self::KEY, $this->clock()->now()->addSeconds($seconds));

        self::assertSame('A single-use key must be recorded until a moment after now.', $exception->getMessage());
        self::assertStringNotContainsString(self::KEY, $exception->getMessage());
    }

    /**
     * An expiry a microsecond before now, in another timezone, is still before
     * now: instants are compared, not wall clocks.
     *
     * @return void
     */
    public function testComparesTheExpiryAsAnInstant(): void
    {
        $until = $this->clock()->now()->subMicrosecond()->setTimezone('Asia/Tokyo');

        $exception = $this->refusal('handoff_code', self::KEY, $until);

        self::assertSame('A single-use key must be recorded until a moment after now.', $exception->getMessage());
    }

    /**
     * The namespace is checked before the key, and the key before the expiry.
     *
     * @return void
     */
    public function testChecksTheNamespaceThenTheKeyThenTheExpiry(): void
    {
        $past = $this->clock()->now()->subMinute();

        self::assertSame(self::NAMESPACE_MESSAGE, $this->refusal('', '', $past)->getMessage());
        self::assertSame('A single-use key must not be empty.', $this->refusal('handoff_code', '', $past)->getMessage());
    }

    /**
     * Record with a store on a fixed clock and return the refusal.
     *
     * @param  string  $namespace
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $until
     * @return \InvalidArgumentException
     *
     * @throws \Throwable
     */
    private function refusal(string $namespace, string $key, CarbonImmutable $until): \InvalidArgumentException
    {
        try {
            (new DatabaseSingleUseStore($this->clock()))->record($namespace, $key, $until);
        } catch (\InvalidArgumentException $exception) {
            return $exception;
        }

        self::fail('Expected the arguments to be refused.');
    }

    /**
     * The fixed clock the store reads.
     *
     * @return \Tests\Fixtures\FixedClock
     */
    private function clock(): FixedClock
    {
        return new FixedClock;
    }
}
