<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
use Tests\Unit\Config\Fixtures\FailingCheck;
use Tests\Unit\Config\Fixtures\InapplicableCheck;
use Tests\Unit\Config\Fixtures\PassingCheck;

/**
 * Unit tests for the configuration checks registry: it starts with the checks
 * it is given (the package's own), adds a check after them in the order added,
 * and refuses a subject already registered or an empty one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationChecks::class)]
final class ConfigurationChecksTest extends TestCase
{
    /** @var array<string, class-string<\SineMacula\Laravel\Sso\Contracts\ConfigurationCheck>> The checks it starts with, standing in for the package's own. */
    private const array OWN = ['features' => PassingCheck::class, 'storage' => InapplicableCheck::class];

    /**
     * It starts with the checks it is given, in their order.
     *
     * @return void
     */
    public function testStartsWithTheChecksItIsGiven(): void
    {
        self::assertSame(self::OWN, (new ConfigurationChecks(self::OWN))->all());
    }

    /**
     * An added check runs after those it started with, in the order added.
     *
     * @return void
     */
    public function testAddsEachCheckAfterThoseBeforeIt(): void
    {
        $checks = new ConfigurationChecks(self::OWN);

        $checks->add('directory', PassingCheck::class);
        $checks->add('provisioning', FailingCheck::class);

        self::assertSame(
            [...self::OWN, 'directory' => PassingCheck::class, 'provisioning' => FailingCheck::class],
            $checks->all(),
        );
    }

    /**
     * Each subject that cannot be added: the package's own, one added before,
     * and an empty one.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function refusedSubjects(): iterable
    {
        yield 'the package\'s own' => ['features', 'A configuration check is already registered under [features].'];
        yield 'one added before' => ['directory', 'A configuration check is already registered under [directory].'];
        yield 'an empty one' => ['', 'A configuration check needs a subject.'];
        yield 'a blank one' => [' ', 'A configuration check needs a subject.'];
    }

    /**
     * A subject already registered, even for the same class, and an empty one
     * are refused, and leave the checks as they were.
     *
     * @param  string  $subject
     * @param  string  $message
     * @return void
     */
    #[DataProvider('refusedSubjects')]
    public function testRefusesASubjectThatIsTakenOrEmpty(string $subject, string $message): void
    {
        $checks = new ConfigurationChecks(self::OWN);

        $checks->add('directory', PassingCheck::class);

        $before = $checks->all();

        try {
            $checks->add($subject, $before[$subject] ?? PassingCheck::class);
            self::fail('The subject was added.');
        } catch (\LogicException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        self::assertSame($before, $checks->all());
    }
}
