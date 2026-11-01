<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Keys\KeySettings;
use Tests\TestCase;

/**
 * Feature tests for the settings of the keys the package generates and rotates
 * (SSO-2.7): the shipped defaults, the digit strings `env()` gives, an RSA
 * modulus of 3072 or 4096 bits only, each range accepted to its bounds and
 * refused past them with a message naming the key, and every value read on each
 * call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeySettings::class)]
final class KeySettingsTest extends TestCase
{
    /**
     * The shipped configuration gives the documented defaults.
     *
     * @return void
     */
    public function testTheShippedDefaults(): void
    {
        $settings = self::settings();

        self::assertSame(3072, $settings->rsaBits());
        self::assertSame(730, $settings->certificateDays());
        self::assertSame(604800, $settings->overlapSeconds());
        self::assertSame(30, $settings->expiryWarningDays());
        self::assertSame('prime256v1', KeySettings::EC_CURVE);
    }

    /**
     * A configuration published before the settings existed takes the same
     * defaults.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        config()->set('sso.keys', []);

        $settings = self::settings();

        self::assertSame(KeySettings::DEFAULT_RSA_BITS, $settings->rsaBits());
        self::assertSame(KeySettings::DEFAULT_CERTIFICATE_DAYS, $settings->certificateDays());
        self::assertSame(KeySettings::DEFAULT_OVERLAP_SECONDS, $settings->overlapSeconds());
        self::assertSame(KeySettings::DEFAULT_EXPIRY_WARNING_DAYS, $settings->expiryWarningDays());
    }

    /**
     * Rows of `[key, value, expected]`: each setting at its bounds, and as the
     * digit string `env()` gives.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: int}>
     */
    public static function provideAcceptedValues(): iterable
    {
        yield from [
            'rsa, 3072'         => ['rsa_bits', 3072, 3072],
            'rsa, 4096'         => ['rsa_bits', 4096, 4096],
            'rsa, a string'     => ['rsa_bits', '4096', 4096],
            'days, least'       => ['certificate_days', 1, 1],
            'days, most'        => ['certificate_days', 3650, 3650],
            'days, a string'    => ['certificate_days', '365', 365],
            'overlap, none'     => ['overlap_seconds', 0, 0],
            'overlap, most'     => ['overlap_seconds', 7776000, 7776000],
            'overlap, a string' => ['overlap_seconds', '3600', 3600],
            'warning, least'    => ['expiry_warning_days', 1, 1],
            'warning, most'     => ['expiry_warning_days', 365, 365],
            'warning, a string' => ['expiry_warning_days', '14', 14],
        ];
    }

    /**
     * Each setting accepts every value in its range.
     *
     * @param  string  $key
     * @param  int|string  $value
     * @param  int  $expected
     * @return void
     */
    #[DataProvider('provideAcceptedValues')]
    public function testAcceptsEachValueWithinItsRange(string $key, int|string $value, int $expected): void
    {
        config()->set('sso.keys.' . $key, $value);

        self::assertSame($expected, self::read($key));
    }

    /**
     * Rows of `[key, value, message]`: each setting past its bounds or
     * malformed, and the exact message it fails with.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideRefusedValues(): iterable
    {
        $rsa     = 'sso.keys.rsa_bits must be one of 3072, 4096.';
        $days    = 'sso.keys.certificate_days must be an integer from 1 to 3650.';
        $overlap = 'sso.keys.overlap_seconds must be an integer from 0 to 7776000.';
        $warning = 'sso.keys.expiry_warning_days must be an integer from 1 to 365.';

        yield from [
            'rsa, 2048'            => ['rsa_bits', 2048, $rsa],
            'rsa, 8192'            => ['rsa_bits', 8192, $rsa],
            'rsa, between'         => ['rsa_bits', 3584, $rsa],
            'rsa, padded'          => ['rsa_bits', '03072', $rsa],
            'rsa, a word'          => ['rsa_bits', 'strong', $rsa],
            'rsa, null'            => ['rsa_bits', null, $rsa],
            'days, none'           => ['certificate_days', 0, $days],
            'days, past'           => ['certificate_days', 3651, $days],
            'days, a fraction'     => ['certificate_days', '1.5', $days],
            'overlap, negative'    => ['overlap_seconds', -1, $overlap],
            'overlap, past'        => ['overlap_seconds', 7776001, $overlap],
            'overlap, a float'     => ['overlap_seconds', 60.0, $overlap],
            'warning, none'        => ['expiry_warning_days', 0, $warning],
            'warning, past'        => ['expiry_warning_days', 366, $warning],
            'warning, a boolean'   => ['expiry_warning_days', true, $warning],
            'warning, signed'      => ['expiry_warning_days', '+30', $warning],
            'warning, an array'    => ['expiry_warning_days', [30], $warning],
            'days, an empty value' => ['certificate_days', '', $days],
        ];
    }

    /**
     * Each setting fails closed outside its range, naming the key, never the
     * value.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesEachValueOutsideItsRange(string $key, mixed $value, string $message): void
    {
        config()->set('sso.keys.' . $key, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::read($key);
    }

    /**
     * Every value is read on each call, so a change applies at once.
     *
     * @return void
     */
    public function testReadsEachValueOnEachCall(): void
    {
        $settings = self::settings();

        config()->set('sso.keys.rsa_bits', 4096);
        config()->set('sso.keys.overlap_seconds', 60);

        self::assertSame(4096, $settings->rsaBits());
        self::assertSame(60, $settings->overlapSeconds());
    }

    /**
     * The settings, read from the application's configuration.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeySettings
     */
    private static function settings(): KeySettings
    {
        return new KeySettings(config());
    }

    /**
     * The setting of the key.
     *
     * @param  string  $key
     * @return int
     */
    private static function read(string $key): int
    {
        $settings = self::settings();

        return match ($key) {
            'rsa_bits'         => $settings->rsaBits(),
            'certificate_days' => $settings->certificateDays(),
            'overlap_seconds'  => $settings->overlapSeconds(),
            default            => $settings->expiryWarningDays(),
        };
    }
}
