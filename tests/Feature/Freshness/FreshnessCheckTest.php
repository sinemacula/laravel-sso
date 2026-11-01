<?php

declare(strict_types = 1);

namespace Tests\Feature\Freshness;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessCheck;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[freshness]`: registered with the boot check, checked
 * while the package is in use, the block an array naming operations only, and
 * each operation's maximum age an integer from 1 to 3600 seconds, reported with
 * the message the gate would fail closed with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessCheck::class)]
final class FreshnessCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /** @var string The problem a block that is not an array is reported with. */
    private const string NOT_AN_ARRAY = '`sso.freshness.max_age_seconds` must be an array of maximum ages by operation.';

    /** @var string The operations an unknown key is reported against, in order. */
    private const string OPERATIONS = 'connection_trust, connection_enable, connection_delete, connection_idp_initiated, keys_rotate, '
        . 'domain_claim, domain_verify, domain_remove, enforcement_update, link_create, link_remove';

    /**
     * The check is registered with the boot check and `sso:check` under
     * `freshness`.
     *
     * @return void
     */
    public function testIsRegisteredUnderFreshness(): void
    {
        self::assertSame(FreshnessCheck::class, SsoServiceProvider::CONFIGURATION_CHECKS['freshness']);
    }

    /**
     * Not checked while the package is not in use, however malformed; the
     * shipped configuration passes once it is.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        $shipped = config('sso.freshness');

        config()->set('sso.freshness.max_age_seconds', 'five minutes');

        self::assertNull($this->problemsOf(FreshnessCheck::class));

        config()->set('sso.freshness.max_age_seconds', ['connection_trusted' => 0]);

        self::assertNull($this->problemsOf(FreshnessCheck::class));

        $this->useThePackage();
        config()->set('sso.freshness', $shipped);

        self::assertSame([], $this->problemsOf(FreshnessCheck::class));
    }

    /**
     * A malformed protocol switch counts as the package in use, so the maximum
     * ages are checked rather than skipped.
     *
     * @return void
     */
    public function testAppliesOverAMalformedProtocolSwitch(): void
    {
        config()->set('sso.features.oidc', 'yes');
        config()->set('sso.freshness.max_age_seconds.link_remove', 3601);

        self::assertSame(['sso.freshness.max_age_seconds.link_remove must be an integer from 1 to 3600.'], $this->problemsOf(FreshnessCheck::class));
    }

    /**
     * An empty block, or none at all, passes: every operation takes the
     * default.
     *
     * @return void
     */
    public function testAnUnsetBlockPasses(): void
    {
        $this->useThePackage();

        config()->set('sso.freshness.max_age_seconds', []);

        self::assertSame([], $this->problemsOf(FreshnessCheck::class));

        config()->set('sso.freshness', []);

        self::assertSame([], $this->problemsOf(FreshnessCheck::class));
    }

    /**
     * Rows of `[block]`: blocks that are not an array.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideBlocksThatAreNotArrays(): iterable
    {
        yield from [
            'an age'          => [300],
            'a digit string'  => ['300'],
            'a word'          => ['five minutes'],
            'an empty string' => [''],
            'null'            => [null],
            'true'            => [true],
        ];
    }

    /**
     * A block that is not an array is reported once; every operation then reads
     * its default, so nothing else is.
     *
     * @param  mixed  $block
     * @return void
     */
    #[DataProvider('provideBlocksThatAreNotArrays')]
    public function testReportsABlockThatIsNotAnArray(mixed $block): void
    {
        $this->useThePackage();

        config()->set('sso.freshness.max_age_seconds', $block);

        self::assertSame([self::NOT_AN_ARRAY], $this->problemsOf(FreshnessCheck::class));
    }

    /**
     * A key that names no operation (a misspelt one would leave the operation
     * meant at its default) is reported by name, with the operations there are.
     *
     * @return void
     */
    public function testReportsAnUnknownOperation(): void
    {
        $this->useThePackage();

        config()->set('sso.freshness.max_age_seconds.connection_trusted', 60);

        self::assertSame(
            ['`sso.freshness.max_age_seconds` has no operation [connection_trusted]; the operations are ' . self::OPERATIONS . '.'],
            $this->problemsOf(FreshnessCheck::class),
        );
    }

    /**
     * Every unknown key is named in one problem, in the block's order, a key
     * given as an operation's stable name and a list's index included.
     *
     * @return void
     */
    public function testReportsEveryUnknownOperationTogether(): void
    {
        $this->useThePackage();

        config()->set('sso.freshness.max_age_seconds', ['sso_link_create' => 60, 'connection_trust' => 60, 'domain' => 60]);

        self::assertSame(
            ['`sso.freshness.max_age_seconds` has no operation [sso_link_create, domain]; the operations are ' . self::OPERATIONS . '.'],
            $this->problemsOf(FreshnessCheck::class),
        );

        config()->set('sso.freshness.max_age_seconds', [300]);

        self::assertSame(
            ['`sso.freshness.max_age_seconds` has no operation [0]; the operations are ' . self::OPERATIONS . '.'],
            $this->problemsOf(FreshnessCheck::class),
        );
    }

    /**
     * Rows of `[value, malformed]`: maximum ages and whether each is refused.
     *
     * @return iterable<string, array{0: mixed, 1: bool}>
     */
    public static function provideAges(): iterable
    {
        yield from [
            'the least'        => [1, false],
            'the greatest'     => [3600, false],
            'a digit string'   => ['600', false],
            'none'             => [0, true],
            'past the ceiling' => [3601, true],
            'negative'         => [-60, true],
            'a float'          => [1.5, true],
            'a decimal string' => ['1.5', true],
            'a word'           => ['five minutes', true],
            'an empty string'  => ['', true],
            'null'             => [null, true],
            'an array'         => [[300], true],
        ];
    }

    /**
     * Each operation's maximum age is checked against the range, and a
     * malformed one reported naming its key.
     *
     * @param  mixed  $value
     * @param  bool  $malformed
     * @return void
     */
    #[DataProvider('provideAges')]
    public function testReportsEachAgeOutOfRange(mixed $value, bool $malformed): void
    {
        $this->useThePackage();

        foreach (FreshnessOperation::cases() as $operation) {
            $key = 'sso.freshness.max_age_seconds.' . $operation->configKey();

            config()->set('sso.freshness.max_age_seconds', [$operation->configKey() => $value]);

            self::assertSame($malformed ? ["{$key} must be an integer from 1 to 3600."] : [], $this->problemsOf(FreshnessCheck::class), $key);
        }
    }

    /**
     * Every malformed age is reported, one problem each, in the order of the
     * operations.
     *
     * @return void
     */
    public function testReportsEveryMalformedAge(): void
    {
        $this->useThePackage();

        $block    = [];
        $problems = [];

        foreach (FreshnessOperation::cases() as $operation) {
            $block[$operation->configKey()] = 0;
            $problems[]                     = 'sso.freshness.max_age_seconds.' . $operation->configKey() . ' must be an integer from 1 to 3600.';
        }

        config()->set('sso.freshness.max_age_seconds', array_reverse($block));

        self::assertSame($problems, $this->problemsOf(FreshnessCheck::class));
    }

    /**
     * An unknown key and a malformed age are both reported, the block's shape
     * first.
     *
     * @return void
     */
    public function testReportsTheShapeBeforeTheAges(): void
    {
        $this->useThePackage();

        config()->set('sso.freshness.max_age_seconds', ['link_remove' => 0, 'links_remove' => 60]);

        self::assertSame([
            '`sso.freshness.max_age_seconds` has no operation [links_remove]; the operations are ' . self::OPERATIONS . '.',
            'sso.freshness.max_age_seconds.link_remove must be an integer from 1 to 3600.',
        ], $this->problemsOf(FreshnessCheck::class));
    }
}
