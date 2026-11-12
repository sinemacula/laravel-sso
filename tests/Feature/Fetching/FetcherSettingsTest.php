<?php

declare(strict_types = 1);

namespace Tests\Feature\Fetching;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use Tests\TestCase;

/**
 * Feature tests for the fetcher's settings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FetcherSettings::class)]
final class FetcherSettingsTest extends TestCase
{
    /** @var string The message of a malformed list of refused ranges. */
    private const string NOT_A_LIST = 'sso.fetcher.refused_ranges must be a list of CIDR ranges.';

    /** @var string The message of a malformed refused range, after its key. */
    private const string NOT_A_RANGE = ' must be a CIDR range: an IPv4 address with /0 to /32, or an IPv6 address with /0 to /128.';

    /**
     * The shipped configuration gives the documented defaults.
     *
     * @return void
     */
    public function testTheShippedDefaults(): void
    {
        $settings = self::settings();

        self::assertSame(10, $settings->timeoutSeconds());
        self::assertSame(5, $settings->connectTimeoutSeconds());
        self::assertSame(1048576, $settings->maxResponseBytes());
        self::assertSame(3, $settings->maxRedirects());
        self::assertSame([], $settings->refusedRanges());
    }

    /**
     * A configuration published before the settings existed takes the defaults.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        config()->set('sso.fetcher', []);

        $settings = self::settings();

        self::assertSame(FetcherSettings::DEFAULT_TIMEOUT_SECONDS, $settings->timeoutSeconds());
        self::assertSame(FetcherSettings::DEFAULT_CONNECT_TIMEOUT_SECONDS, $settings->connectTimeoutSeconds());
        self::assertSame(FetcherSettings::DEFAULT_MAX_RESPONSE_BYTES, $settings->maxResponseBytes());
        self::assertSame(FetcherSettings::DEFAULT_MAX_REDIRECTS, $settings->maxRedirects());
        self::assertSame([], $settings->refusedRanges());

        $settings->validate();
    }

    /**
     * Rows of `[key, value, expected]`: each integer setting at its bounds and
     * as an `env()` string.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: int}>
     */
    public static function provideAcceptedIntegers(): iterable
    {
        yield from [
            'timeout, least'      => ['timeout_seconds', 1, 1],
            'timeout, most'       => ['timeout_seconds', 60, 60],
            'timeout, a string'   => ['timeout_seconds', '30', 30],
            'connect, least'      => ['connect_timeout_seconds', 1, 1],
            'connect, most'       => ['connect_timeout_seconds', 30, 30],
            'connect, a string'   => ['connect_timeout_seconds', '7', 7],
            'size, least'         => ['max_response_bytes', 1024, 1024],
            'size, most'          => ['max_response_bytes', 10485760, 10485760],
            'size, a string'      => ['max_response_bytes', '2048', 2048],
            'redirects, none'     => ['max_redirects', 0, 0],
            'redirects, most'     => ['max_redirects', 10, 10],
            'redirects, a string' => ['max_redirects', '5', 5],
        ];
    }

    /**
     * Each integer setting accepts every value in its range.
     *
     * @param  string  $key
     * @param  int|string  $value
     * @param  int  $expected
     * @return void
     */
    #[DataProvider('provideAcceptedIntegers')]
    public function testAcceptsEachIntegerWithinItsRange(string $key, int|string $value, int $expected): void
    {
        config()->set('sso.fetcher.' . $key, $value);

        self::assertSame($expected, self::read(self::settings(), $key));
    }

    /**
     * Rows of `[key, value, message]`: each integer setting out of range or
     * malformed.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideRefusedIntegers(): iterable
    {
        $timeout   = 'sso.fetcher.timeout_seconds must be an integer from 1 to 60.';
        $connect   = 'sso.fetcher.connect_timeout_seconds must be an integer from 1 to 30.';
        $size      = 'sso.fetcher.max_response_bytes must be an integer from 1024 to 10485760.';
        $redirects = 'sso.fetcher.max_redirects must be an integer from 0 to 10.';

        yield from [
            'timeout, none'        => ['timeout_seconds', 0, $timeout],
            'timeout, past'        => ['timeout_seconds', 61, $timeout],
            'timeout, a fraction'  => ['timeout_seconds', '1.5', $timeout],
            'timeout, null'        => ['timeout_seconds', null, $timeout],
            'timeout, a word'      => ['timeout_seconds', 'ten', $timeout],
            'connect, none'        => ['connect_timeout_seconds', 0, $connect],
            'connect, past'        => ['connect_timeout_seconds', 31, $connect],
            'connect, padded'      => ['connect_timeout_seconds', '05', $connect],
            'connect, a float'     => ['connect_timeout_seconds', 5.0, $connect],
            'size, below'          => ['max_response_bytes', 1023, $size],
            'size, past'           => ['max_response_bytes', 10485761, $size],
            'size, signed'         => ['max_response_bytes', '+2048', $size],
            'size, an array'       => ['max_response_bytes', [2048], $size],
            'redirects, negative'  => ['max_redirects', -1, $redirects],
            'redirects, past'      => ['max_redirects', 11, $redirects],
            'redirects, a boolean' => ['max_redirects', true, $redirects],
            'redirects, empty'     => ['max_redirects', '', $redirects],
        ];
    }

    /**
     * Each integer setting fails closed out of range, naming the key and range,
     * never the value.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedIntegers')]
    public function testRefusesEachIntegerOutsideItsRange(string $key, mixed $value, string $message): void
    {
        config()->set('sso.fetcher.' . $key, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::read(self::settings(), $key);
    }

    /**
     * Rows of `[ranges]`: lists of valid CIDR ranges.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideAcceptedRanges(): iterable
    {
        yield from [
            'none'                => [[]],
            'an ipv4 range'       => [['203.0.113.0/24']],
            'an ipv4 host'        => [['8.8.8.8/32']],
            'every ipv4 address'  => [['0.0.0.0/0']],
            'an ipv6 range'       => [['2606:4700::/32']],
            'an ipv6 host'        => [['2606:4700:4700::1111/128']],
            'every ipv6 address'  => [['::/0']],
            'host bits set'       => [['10.1.2.3/8']],
            'mixed'               => [['8.8.8.0/24', 'fd00::/8', '2001:db8::/48']],
            'a mapped ipv6 range' => [['::ffff:10.0.0.0/104']],
        ];
    }

    /**
     * A list of valid CIDR ranges is answered as configured.
     *
     * @param  list<string>  $ranges
     * @return void
     */
    #[DataProvider('provideAcceptedRanges')]
    public function testAcceptsAListOfCidrRanges(array $ranges): void
    {
        config()->set('sso.fetcher.refused_ranges', $ranges);

        self::assertSame($ranges, self::settings()->refusedRanges());
    }

    /**
     * Rows of `[ranges, message]`: malformed lists and ranges, and the message
     * each fails with.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideRefusedRanges(): iterable
    {
        yield from [
            'a string'                => ['10.0.0.0/8', self::NOT_A_LIST],
            'null'                    => [null, self::NOT_A_LIST],
            'keyed'                   => [['office' => '10.0.0.0/8'], self::NOT_A_LIST],
            'not a string'            => [[24], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'no prefix'               => [['10.0.0.0'], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'an ipv4 prefix past 32'  => [['10.0.0.0/33'], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'an ipv6 prefix past 128' => [['::/129'], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'a padded prefix'         => [['10.0.0.0/08'], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'a short address'         => [['10.0.0/8'], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'a padded address'        => [['010.0.0.0/8'], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'a zone'                  => [['fe80::1%eth0/64'], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'a name'                  => [['example.com/32'], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'trailing space'          => [['10.0.0.0/8 '], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'a newline'               => [["10.0.0.0/8\n"], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'a negative prefix'       => [['10.0.0.0/-1'], 'sso.fetcher.refused_ranges.0' . self::NOT_A_RANGE],
            'the second'              => [['10.0.0.0/8', '10.0.0.0/8/8'], 'sso.fetcher.refused_ranges.1' . self::NOT_A_RANGE],
        ];
    }

    /**
     * A malformed list or entry fails closed naming its key, never the value.
     *
     * @param  mixed  $ranges
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedRanges')]
    public function testRefusesAMalformedRange(mixed $ranges, string $message): void
    {
        config()->set('sso.fetcher.refused_ranges', $ranges);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings()->refusedRanges();
    }

    /**
     * `isRange()` answers for a single range as the list's check does.
     *
     * @return void
     */
    public function testIsRangeJudgesOneRange(): void
    {
        self::assertTrue(FetcherSettings::isRange('10.0.0.0/8'));
        self::assertTrue(FetcherSettings::isRange('10.0.0.0/32'));
        self::assertTrue(FetcherSettings::isRange('::/128'));
        self::assertFalse(FetcherSettings::isRange('10.0.0.0/33'));
        self::assertFalse(FetcherSettings::isRange('::/129'));
        self::assertFalse(FetcherSettings::isRange('10.0.0.0'));
        self::assertFalse(FetcherSettings::isRange('/8'));
    }

    /**
     * `validate()` passes for valid settings, including a connect timeout equal
     * to the timeout.
     *
     * @return void
     */
    public function testValidatePassesForValidSettings(): void
    {
        config()->set('sso.fetcher.timeout_seconds', 5);
        config()->set('sso.fetcher.connect_timeout_seconds', 5);
        config()->set('sso.fetcher.refused_ranges', ['8.8.8.0/24']);

        self::settings()->validate();

        $this->addToAssertionCount(1);
    }

    /**
     * `validate()` refuses a connect timeout longer than the timeout.
     *
     * @return void
     */
    public function testValidateRefusesAConnectTimeoutLongerThanTheTimeout(): void
    {
        config()->set('sso.fetcher.timeout_seconds', 5);
        config()->set('sso.fetcher.connect_timeout_seconds', 6);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(FetcherSettings::CONNECT_TIMEOUT_EXCEEDS_TIMEOUT);

        self::settings()->validate();
    }

    /**
     * Rows of `[key, value, message]`: one malformed setting each, and
     * `validate()`'s message.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideInvalidSettings(): iterable
    {
        yield from [
            'the timeout'    => ['timeout_seconds', 0, 'sso.fetcher.timeout_seconds must be an integer from 1 to 60.'],
            'the connect'    => ['connect_timeout_seconds', 0, 'sso.fetcher.connect_timeout_seconds must be an integer from 1 to 30.'],
            'the size'       => ['max_response_bytes', 0, 'sso.fetcher.max_response_bytes must be an integer from 1024 to 10485760.'],
            'the redirects'  => ['max_redirects', 11, 'sso.fetcher.max_redirects must be an integer from 0 to 10.'],
            'the ranges'     => ['refused_ranges', 'none', self::NOT_A_LIST],
            'the connection' => ['connect_timeout_seconds', 11, FetcherSettings::CONNECT_TIMEOUT_EXCEEDS_TIMEOUT],
        ];
    }

    /**
     * `validate()` reads every setting, so each malformed one fails it.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideInvalidSettings')]
    public function testValidateReadsEverySetting(string $key, mixed $value, string $message): void
    {
        config()->set('sso.fetcher.' . $key, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings()->validate();
    }

    /**
     * Every value is read on each call, so a change is seen by the next
     * request.
     *
     * @return void
     */
    public function testReadsEachValueOnEachCall(): void
    {
        $settings = self::settings();

        config()->set('sso.fetcher.timeout_seconds', 20);
        config()->set('sso.fetcher.connect_timeout_seconds', 2);
        config()->set('sso.fetcher.max_response_bytes', 4096);
        config()->set('sso.fetcher.max_redirects', 0);
        config()->set('sso.fetcher.refused_ranges', ['8.8.8.8/32']);

        self::assertSame(20, $settings->timeoutSeconds());
        self::assertSame(2, $settings->connectTimeoutSeconds());
        self::assertSame(4096, $settings->maxResponseBytes());
        self::assertSame(0, $settings->maxRedirects());
        self::assertSame(['8.8.8.8/32'], $settings->refusedRanges());
    }

    /**
     * The settings over the test application's configuration.
     *
     * @return \SineMacula\Laravel\Sso\Fetching\FetcherSettings
     */
    private static function settings(): FetcherSettings
    {
        return new FetcherSettings(config());
    }

    /**
     * The integer setting under the key.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetcherSettings  $settings
     * @param  string  $key
     * @return int
     */
    private static function read(FetcherSettings $settings, string $key): int
    {
        return match ($key) {
            'timeout_seconds'         => $settings->timeoutSeconds(),
            'connect_timeout_seconds' => $settings->connectTimeoutSeconds(),
            'max_response_bytes'      => $settings->maxResponseBytes(),
            default                   => $settings->maxRedirects(),
        };
    }
}
