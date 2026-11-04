<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Config\ConfigurationChecks;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Unit\Config\Fixtures\FailingCheck;
use Tests\Unit\Config\Fixtures\PassingCheck;

/**
 * Unit tests for the configuration checks registry: it starts with the
 * package's own checks, adds a check after them in the order added, and refuses
 * a subject already registered or an empty one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationChecks::class)]
final class ConfigurationChecksTest extends TestCase
{
    /**
     * It starts with the package's own checks, in their order.
     *
     * @return void
     */
    public function testStartsWithThePackagesOwnChecks(): void
    {
        self::assertSame(SsoServiceProvider::CONFIGURATION_CHECKS, (new ConfigurationChecks)->all());
    }

    /**
     * An added check runs after the package's own, in the order added.
     *
     * @return void
     */
    public function testAddsEachCheckAfterThoseBeforeIt(): void
    {
        $checks = new ConfigurationChecks;

        $checks->add('directory', PassingCheck::class);
        $checks->add('provisioning', FailingCheck::class);

        self::assertSame(
            [...SsoServiceProvider::CONFIGURATION_CHECKS, 'directory' => PassingCheck::class, 'provisioning' => FailingCheck::class],
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
        $checks = new ConfigurationChecks;

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
