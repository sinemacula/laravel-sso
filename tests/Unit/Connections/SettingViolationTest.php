<?php

declare(strict_types = 1);

namespace Tests\Unit\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;

/**
 * Unit tests for a setting violation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SettingViolation::class)]
final class SettingViolationTest extends TestCase
{
    /**
     * A violation names its setting and code, and serialises as both.
     *
     * @return void
     */
    public function testNamesItsSettingAndCode(): void
    {
        $violation = new SettingViolation('extra_parameters.state', ViolationCode::RESERVED);

        self::assertSame('extra_parameters.state', $violation->setting);
        self::assertSame(ViolationCode::RESERVED, $violation->code);
        self::assertSame('{"setting":"extra_parameters.state","code":"reserved"}', json_encode($violation));
    }

    /**
     * A violation names a setting of 1 to 255 bytes.
     *
     * @return void
     */
    public function testRefusesAnEmptyOrOverlongSetting(): void
    {
        new SettingViolation(str_repeat('a', SettingViolation::MAX_SETTING_LENGTH), ViolationCode::REQUIRED);

        foreach (['', str_repeat('a', SettingViolation::MAX_SETTING_LENGTH + 1)] as $setting) {

            try {
                new SettingViolation($setting, ViolationCode::REQUIRED);
                self::fail('The setting was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A violation names a setting of 1 to 255 bytes.', $exception->getMessage());
            }
        }
    }
}
