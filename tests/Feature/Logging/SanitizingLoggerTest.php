<?php

declare(strict_types = 1);

namespace Tests\Feature\Logging;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use Tests\Concerns\CapturesLogs;
use Tests\TestCase;

/**
 * Feature tests for the package's logger (SSO-5.7, SSO-9.8, SSO-11.9): every
 * level written to the configured channel, or the default one, the channel
 * resolved on each call, the message sanitised and the context redacted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SanitizingLogger::class)]
final class SanitizingLoggerTest extends TestCase
{
    use CapturesLogs;

    /**
     * The logger is a PSR-3 logger the container builds.
     *
     * @return void
     */
    public function testIsAPsrLogger(): void
    {
        self::assertInstanceOf(LoggerInterface::class, $this->logger());
    }

    /**
     * Rows of `[level]`: every level PSR-3 defines.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideLevels(): iterable
    {
        foreach ([LogLevel::EMERGENCY, LogLevel::ALERT, LogLevel::CRITICAL, LogLevel::ERROR, LogLevel::WARNING, LogLevel::NOTICE, LogLevel::INFO, LogLevel::DEBUG] as $level) {
            yield $level => [$level];
        }
    }

    /**
     * Each level, through its own method and through `log()`, is written to the
     * configured channel at that level.
     *
     * @param  string  $level
     * @return void
     */
    #[DataProvider('provideLevels')]
    public function testWritesEachLevelToTheConfiguredChannel(string $level): void
    {
        $this->captureLogs();

        $logger = $this->logger();

        self::methodFor($logger, $level)('By its method.', ['reference' => 'ref-1']);
        $logger->log($level, 'Through log().', ['reference' => 'ref-2']);

        self::assertSame([
            ['channel' => 'sso_capture', 'level' => $level, 'message' => 'By its method.', 'context' => ['reference' => 'ref-1']],
            ['channel' => 'sso_capture', 'level' => $level, 'message' => 'Through log().', 'context' => ['reference' => 'ref-2']],
        ], $this->capturedLogRecords());
    }

    /**
     * A level PSR-3 does not define is refused with PSR-3's exception, and
     * nothing is written.
     *
     * @return void
     */
    public function testRefusesAnUnknownLevel(): void
    {
        $this->captureLogs();

        foreach (['verbose', 'INFO', 200, null] as $level) {
            try {
                $this->logger()->log($level, 'Refused.');
                self::fail('An unknown level was accepted.');
            } catch (InvalidArgumentException $exception) {
                self::assertSame('The level must be one of the levels PSR-3 defines.', $exception->getMessage());
            }
        }

        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * The message is sanitised as a diagnostic: controls removed, secrets
     * redacted and the length capped. A `Stringable` message is cast first.
     *
     * @return void
     */
    public function testSanitizesTheMessage(): void
    {
        $this->captureLogs();

        $message = new class implements \Stringable {
            /**
             * The message's text.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return "Token refused:\n{\"access_token\":\"abc\"}";
            }
        };

        $logger = $this->logger();

        $logger->error("Callback refused\u{202E} at https://app.example.com/cb?code=abc&state=xyz");
        $logger->error($message);

        config()->set('sso.logging.max_diagnostic_length', 64);

        $logger->error(str_repeat('word ', 20));

        self::assertSame([
            'Callback refused at https://app.example.com/cb?code=[redacted]&state=[redacted]',
            'Token refused: {"access_token":"[redacted]"}',
            str_repeat('word ', 12) . 'wor…',
        ], array_column($this->capturedLogRecords(), 'message'));
    }

    /**
     * The context is redacted before it reaches the channel.
     *
     * @return void
     */
    public function testRedactsTheContext(): void
    {
        $this->captureLogs();

        $this->logger()->warning('Completion refused.', [
            'request_reference' => 'ref-1',
            'reason'            => FailureReason::SIGNATURE_INVALID,
            'state'             => 'the-state',
            'provider'          => ['error' => 'invalid_grant', 'refresh_token' => 'the-refresh-token'],
            'exception'         => new \RuntimeException("Handoff code=the-code\nrefused", 7),
        ]);

        self::assertSame([
            'request_reference' => 'ref-1',
            'reason'            => 'signature_invalid',
            'state'             => '[redacted]',
            'provider'          => ['error' => 'invalid_grant', 'refresh_token' => '[redacted]'],
            'exception'         => ['class' => \RuntimeException::class, 'message' => 'Handoff code=[redacted] refused', 'code' => 7],
        ], $this->capturedLogRecords()[0]['context']);

        $this->assertNothingLoggedContains('the-state', 'the-refresh-token', 'the-code');
    }

    /**
     * The message and the context redact the same keys, decoded, and the whole
     * value under each, whatever it holds: punctuation, an encoded name or a
     * JSON array.
     *
     * @return void
     */
    public function testRedactsWholeValuesUnderEncodedKeys(): void
    {
        $this->captureLogs();

        $this->logger()->error('Refused: client_secret=alpha,beta ?client%5fsecret=short-secret {"access_token":["short-token-value"]}', [
            'client%5Fsecret' => 'gamma',
            'form'            => ['user[password]' => 'delta', 'grant' => 'refresh_token=epsilon;zeta'],
        ]);

        $record = $this->capturedLogRecords()[0];

        self::assertSame('Refused: client_secret=[redacted] ?client%5fsecret=[redacted] {"access_token":"[redacted]"}', $record['message']);
        self::assertSame(['client%5Fsecret' => '[redacted]', 'form' => ['user[password]' => '[redacted]', 'grant' => 'refresh_token=[redacted]']], $record['context']);

        $this->assertNothingLoggedContains('alpha', 'beta', 'short-secret', 'short-token-value', 'gamma', 'delta', 'epsilon', 'zeta');
    }

    /**
     * With no channel configured, the package logs to Laravel's default
     * channel.
     *
     * @return void
     */
    public function testUsesTheDefaultChannelWhenNoneIsConfigured(): void
    {
        $this->captureLogs('sso_default');
        $this->captureLogs('sso_other');

        config()->set('logging.default', 'sso_default');
        config()->set('sso.logging.channel', null);

        $this->logger()->info('To the default channel.');

        self::assertSame(['To the default channel.'], array_column($this->capturedLogRecords('sso_default'), 'message'));
        self::assertSame([], $this->capturedLogRecords('sso_other'));
    }

    /**
     * The channel is resolved on each call, so a change of
     * `sso.logging.channel` between two calls is honoured by one logger.
     *
     * @return void
     */
    public function testResolvesTheChannelOnEachCall(): void
    {
        $this->captureLogs('sso_first');
        $this->captureLogs('sso_second');

        $logger = $this->logger();

        config()->set('sso.logging.channel', 'sso_first');
        $logger->notice('First.');

        config()->set('sso.logging.channel', 'sso_second');
        $logger->notice('Second.');

        self::assertSame(['First.'], array_column($this->capturedLogRecords('sso_first'), 'message'));
        self::assertSame(['Second.'], array_column($this->capturedLogRecords('sso_second'), 'message'));
    }

    /**
     * A malformed setting fails closed: nothing is written rather than a
     * message logged unsanitised or to an unintended place.
     *
     * @return void
     */
    public function testAMalformedSettingFailsClosed(): void
    {
        $this->captureLogs();

        config()->set('sso.logging.redacted_keys', 'tenant_secret');

        try {
            $this->logger()->log(LogLevel::ERROR, 'code=abc');
            self::fail('A malformed setting was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('sso.logging.redacted_keys', $exception->getMessage());
        }

        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * The logger's own method for the level, as `error()` is for `error`.
     *
     * @param  \SineMacula\Laravel\Sso\Logging\SanitizingLogger  $logger
     * @param  string  $level
     * @return \Closure(string|\Stringable, array<array-key, mixed>): void
     *
     * @throws \LogicException
     */
    private static function methodFor(SanitizingLogger $logger, string $level): \Closure
    {
        return match ($level) {
            LogLevel::EMERGENCY => $logger->emergency(...),
            LogLevel::ALERT     => $logger->alert(...),
            LogLevel::CRITICAL  => $logger->critical(...),
            LogLevel::ERROR     => $logger->error(...),
            LogLevel::WARNING   => $logger->warning(...),
            LogLevel::NOTICE    => $logger->notice(...),
            LogLevel::INFO      => $logger->info(...),
            LogLevel::DEBUG     => $logger->debug(...),
            default             => throw new \LogicException('No method logs at the level [' . $level . '].'),
        };
    }

    /**
     * The logger, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Logging\SanitizingLogger
     */
    private function logger(): SanitizingLogger
    {
        return app(SanitizingLogger::class);
    }
}
