<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Keys\KeysCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[keys]`: checked only while the package is in use, the
 * shipped defaults passing, and each malformed setting reported with the
 * message the key operations would fail closed with, naming its key (SSO-2.7).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeysCheck::class)]
final class KeysCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * Not checked while the package is not in use, however malformed; the
     * shipped defaults pass once it is.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        config()->set('sso.keys.rsa_bits', 1024);

        self::assertNull($this->problemsOf(KeysCheck::class));

        $this->useThePackage();
        config()->set('sso.keys.rsa_bits', 3072);

        self::assertSame([], $this->problemsOf(KeysCheck::class));
    }

    /**
     * Settings that are not configured at all take their defaults and pass.
     *
     * @return void
     */
    public function testUnsetSettingsPass(): void
    {
        $this->useThePackage();

        config()->set('sso.keys', ['table' => 'sso_keys']);

        self::assertSame([], $this->problemsOf(KeysCheck::class));
    }

    /**
     * Rows of `[settings, problems]`: key settings and what each reports.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function provideSettings(): iterable
    {
        $rsa     = 'sso.keys.rsa_bits must be one of 3072, 4096.';
        $days    = 'sso.keys.certificate_days must be an integer from 1 to 3650.';
        $overlap = 'sso.keys.overlap_seconds must be an integer from 0 to 7776000.';
        $warning = 'sso.keys.expiry_thresholds must be a list of distinct integers from 0 to 365, including 0.';
        $claim   = 'sso.keys.expiry_claim_seconds must be an integer from 1 to 3600.';

        yield from [
            'valid strings' => [
                ['rsa_bits' => '4096', 'certificate_days' => '365', 'overlap_seconds' => '0', 'expiry_thresholds' => ['7', 0], 'expiry_claim_seconds' => '60'],
                [],
            ],
            'a weak rsa modulus'    => [['rsa_bits' => 2048], [$rsa]],
            'a malformed validity'  => [['certificate_days' => 0], [$days]],
            'a malformed overlap'   => [['overlap_seconds' => 7776001], [$overlap]],
            'malformed thresholds'  => [['expiry_thresholds' => 'soon'], [$warning]],
            'a malformed claim'     => [['expiry_claim_seconds' => 0], [$claim]],
            'every problem at once' => [
                ['rsa_bits' => 'big', 'certificate_days' => 3651, 'overlap_seconds' => -1, 'expiry_thresholds' => [366], 'expiry_claim_seconds' => 3601],
                [$rsa, $days, $overlap, $warning, $claim],
            ],
        ];
    }

    /**
     * Each setting reports exactly its problem, every one in a run.
     *
     * @param  array<string, mixed>  $settings
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideSettings')]
    public function testReportsEachProblem(array $settings, array $problems): void
    {
        $this->useThePackage();

        foreach ($settings as $key => $value) {
            config()->set('sso.keys.' . $key, $value);
        }

        self::assertSame($problems, $this->problemsOf(KeysCheck::class));
    }
}
