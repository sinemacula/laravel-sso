<?php

declare(strict_types = 1);

namespace Tests\Feature\Logging;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Logging\LoggingSettings;
use SineMacula\Laravel\Sso\Logging\Redactor;
use Tests\TestCase;

/**
 * Feature tests for the logging settings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LoggingSettings::class)]
final class LoggingSettingsTest extends TestCase
{
    /** @var string The message a malformed channel fails closed with. */
    private const string CHANNEL = '`sso.logging.channel` must be the name of a channel in `logging.channels`, or null or empty for the default channel.';

    /** @var string The message a malformed diagnostic length fails closed with. */
    private const string LENGTH = 'sso.logging.max_diagnostic_length must be an integer from 64 to 4096.';

    /** @var string The message malformed redacted keys fail closed with. */
    private const string KEYS = '`sso.logging.redacted_keys` must be a list of key names, each holding a letter or a digit.';

    /**
     * The shipped configuration uses the default channel, 512 characters and
     * the built-in keys.
     *
     * @return void
     */
    public function testTheShippedDefaults(): void
    {
        $settings = $this->settings();

        self::assertNull($settings->channel());
        self::assertSame(512, $settings->maxDiagnosticLength());
        self::assertSame(self::builtInKeys(), $settings->redactedKeys());

        $settings->assertChannelConfigured();
        $settings->validate();
    }

    /**
     * Unset settings take the defaults.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        config()->set('sso.logging', []);

        $settings = $this->settings();

        self::assertNull($settings->channel());
        self::assertSame(512, $settings->maxDiagnosticLength());
        self::assertSame(self::builtInKeys(), $settings->redactedKeys());
    }

    /**
     * The built-in keys normalise to distinct keys.
     *
     * @return void
     */
    public function testTheBuiltInKeysAreNormalized(): void
    {
        $keys = $this->settings()->redactedKeys();

        self::assertSame(array_values(array_unique($keys)), $keys);
        self::assertContains('clientsecret', $keys);
        self::assertContains('samlresponse', $keys);
        self::assertContains('setcookie', $keys);
        self::assertNotContains('client_secret', $keys);

        foreach ($keys as $key) {
            self::assertMatchesRegularExpression('/^[a-z0-9]+$/', $key);
        }
    }

    /**
     * Rows of `[key, normalised]`: keys and the form they are compared in.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideKeys(): iterable
    {
        yield from [
            'snake case'  => ['client_secret', 'clientsecret'],
            'kebab title' => ['Client-Secret', 'clientsecret'],
            'upper case'  => ['CLIENT_SECRET', 'clientsecret'],
            'camel case'  => ['clientSecret', 'clientsecret'],
            'with digits' => ['x509_certificate', 'x509certificate'],
            'punctuation' => ['--', ''],
            'non-ASCII'   => ['clé', 'cl'],
        ];
    }

    /**
     * A key normalises to lower case with only `a-z` and `0-9` kept.
     *
     * @param  string  $key
     * @param  string  $normalized
     * @return void
     */
    #[DataProvider('provideKeys')]
    public function testNormalizesAKey(string $key, string $normalized): void
    {
        self::assertSame($normalized, LoggingSettings::normalizeKey($key));
    }

    /**
     * A configured channel is named; an empty one is the default channel.
     *
     * @return void
     */
    public function testReadsTheChannel(): void
    {
        config()->set('sso.logging.channel', 'single');

        self::assertSame('single', $this->settings()->channel());

        config()->set('sso.logging.channel', '');

        self::assertNull($this->settings()->channel());
    }

    /**
     * Rows of `[value]`: channels that are not a name or none.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedChannels(): iterable
    {
        yield from [
            'an integer' => [1],
            'a boolean'  => [true],
            'an array'   => [['single']],
            'an object'  => [new \stdClass],
        ];
    }

    /**
     * A channel that is not a name or none fails closed, naming the key.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedChannels')]
    public function testRefusesAMalformedChannel(mixed $value): void
    {
        config()->set('sso.logging.channel', $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::CHANNEL);

        $this->settings()->channel();
    }

    /**
     * A channel `logging.channels` does not configure is refused, naming the
     * key and channel.
     *
     * @return void
     */
    public function testRefusesAnUnknownChannel(): void
    {
        $settings = $this->settings();

        config()->set('sso.logging.channel', 'single');
        $settings->assertChannelConfigured();

        config()->set('sso.logging.channel', null);
        $settings->assertChannelConfigured();

        config()->set('sso.logging.channel', 'missing');

        foreach ([$settings->assertChannelConfigured(...), $settings->validate(...)] as $check) {
            try {
                $check();
                self::fail('An unknown channel was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('`sso.logging.channel` names the channel [missing], which is not configured in `logging.channels`.', $exception->getMessage());
            }
        }

        self::assertSame('missing', $settings->channel());
    }

    /**
     * A channel is unknown when `logging.channels` is missing or malformed.
     *
     * @return void
     */
    public function testAChannelIsUnknownWithoutItsConfiguration(): void
    {
        config()->set('sso.logging.channel', 'single');
        config()->set('logging.channels.single', 'not a channel');

        $this->assertUnknownChannel();

        config()->set('logging.channels', 'not channels');

        $this->assertUnknownChannel();
    }

    /**
     * Rows of `[value, length]`: the diagnostic lengths accepted.
     *
     * @return iterable<string, array{0: int|string, 1: int}>
     */
    public static function provideAcceptedLengths(): iterable
    {
        yield from [
            'the least'           => [64, 64],
            'the default'         => [512, 512],
            'the greatest'        => [4096, 4096],
            'a digit string'      => ['1024', 1024],
            'the least, a string' => ['64', 64],
        ];
    }

    /**
     * Each accepted length is the cap, in characters.
     *
     * @param  int|string  $value
     * @param  int  $length
     * @return void
     */
    #[DataProvider('provideAcceptedLengths')]
    public function testAcceptsALengthFrom64To4096(int|string $value, int $length): void
    {
        config()->set('sso.logging.max_diagnostic_length', $value);

        self::assertSame($length, $this->settings()->maxDiagnosticLength());
    }

    /**
     * Rows of `[value]`: diagnostic lengths that are not an integer from 64 to
     * 4096.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedLengths(): iterable
    {
        yield from [
            'below the least'   => [63],
            'past the greatest' => [4097],
            'none'              => [0],
            'negative'          => [-512],
            'a decimal string'  => ['512.5'],
            'a float'           => [512.0],
            'null'              => [null],
            'an empty string'   => [''],
            'padded'            => ['0512'],
            'a word'            => ['long'],
            'a boolean'         => [true],
            'an array'          => [[512]],
        ];
    }

    /**
     * A length outside 64 to 4096 fails closed, naming the key and the range.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedLengths')]
    public function testRefusesAnyOtherLength(mixed $value): void
    {
        config()->set('sso.logging.max_diagnostic_length', $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::LENGTH);

        $this->settings()->maxDiagnosticLength();
    }

    /**
     * Configured keys are added to the built-in ones, so none can be removed.
     *
     * @return void
     */
    public function testAddsConfiguredKeys(): void
    {
        config()->set('sso.logging.redacted_keys', ['X-Tenant-Secret', 'x_tenant_secret', 'Client-Secret', 'apiKey2']);

        self::assertSame([...self::builtInKeys(), 'xtenantsecret', 'apikey2'], $this->settings()->redactedKeys());
    }

    /**
     * Rows of `[value]`: redacted keys that are not a list of key names.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedKeys(): iterable
    {
        yield from [
            'a string'              => ['client_secret'],
            'null'                  => [null],
            'a map'                 => [['secret' => 'tenant_secret']],
            'an empty name'         => [['']],
            'punctuation only'      => [['--']],
            'whitespace only'       => [[' ']],
            'an integer'            => [[1]],
            'null in the list'      => [[null]],
            'a list in the list'    => [[['tenant_secret']]],
            'a good and a bad name' => [['tenant_secret', '']],
        ];
    }

    /**
     * Keys that are not a list of names fail closed, naming the key.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedKeys')]
    public function testRefusesMalformedKeys(mixed $value): void
    {
        config()->set('sso.logging.redacted_keys', $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::KEYS);

        $this->settings()->redactedKeys();
    }

    /**
     * `validate()` fails on each malformed setting.
     *
     * @return void
     */
    public function testValidateFailsOnEachMalformedSetting(): void
    {
        $settings  = $this->settings();
        $malformed = [
            'sso.logging.channel'               => [true, self::CHANNEL],
            'sso.logging.max_diagnostic_length' => [63, self::LENGTH],
            'sso.logging.redacted_keys'         => [[''], self::KEYS],
        ];

        foreach ($malformed as $key => [$value, $message]) {

            $original = config($key);

            config()->set($key, $value);

            try {
                $settings->validate();
                self::fail("A malformed {$key} was accepted.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }

            config()->set($key, $original);
        }

        $settings->validate();
    }

    /**
     * Every setting is read on each call.
     *
     * @return void
     */
    public function testIsReadOnEachCall(): void
    {
        $settings = $this->settings();

        config()->set('sso.logging.channel', 'single');
        config()->set('sso.logging.max_diagnostic_length', 100);
        config()->set('sso.logging.redacted_keys', ['first']);

        self::assertSame('single', $settings->channel());
        self::assertSame(100, $settings->maxDiagnosticLength());
        self::assertContains('first', $settings->redactedKeys());

        config()->set('sso.logging.channel', 'daily');
        config()->set('sso.logging.max_diagnostic_length', '200');
        config()->set('sso.logging.redacted_keys', ['second']);

        self::assertSame('daily', $settings->channel());
        self::assertSame(200, $settings->maxDiagnosticLength());
        self::assertContains('second', $settings->redactedKeys());
        self::assertNotContains('first', $settings->redactedKeys());
    }

    /**
     * The built-in keys, normalised, each once, in order.
     *
     * @return list<string>
     */
    private static function builtInKeys(): array
    {
        return array_values(array_unique(array_map(LoggingSettings::normalizeKey(...), Redactor::REDACTED_KEYS)));
    }

    /**
     * Assert that the configured channel is refused as unknown.
     *
     * @return void
     */
    private function assertUnknownChannel(): void
    {
        try {
            $this->settings()->assertChannelConfigured();
            self::fail('An unconfigured channel was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('which is not configured in `logging.channels`', $exception->getMessage());
        }
    }

    /**
     * The settings, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Logging\LoggingSettings
     */
    private function settings(): LoggingSettings
    {
        return app(LoggingSettings::class);
    }
}
