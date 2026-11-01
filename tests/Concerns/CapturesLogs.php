<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Monolog\LogRecord;

/**
 * Captures what the package logs, in memory, so a test can run a flow and
 * assert that no verifier, code, state, assertion or token reached a log
 * (SSO-9.8, SSO-11.9).
 *
 * `captureLogs()` configures a channel backed by a Monolog `TestHandler` and
 * points `sso.logging.channel` at it, so everything the package logs through
 * `SanitizingLogger` lands there, as it would on a real channel: after
 * sanitising and redaction, and after Laravel's own processing. A test of which
 * channel is used captures several, each under its own name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait CapturesLogs
{
    /** @var array<string, \Monolog\Handler\TestHandler> The handler of each channel captured, by its name. */
    private array $logCaptures = [];

    /**
     * Capture the channel: configure it, backed by an in-memory handler, and
     * point the package's logging at it.
     *
     * @param  string  $channel
     * @return \Monolog\Handler\TestHandler
     */
    protected function captureLogs(string $channel = 'sso_capture'): TestHandler
    {
        $handler = new TestHandler;

        config()->set('logging.channels.' . $channel, [
            'driver' => 'custom',
            'via'    => static fn (): Logger => new Logger($channel, [$handler]),
        ]);

        /** @var \Illuminate\Log\LogManager $logs */
        $logs = app('log');
        $logs->forgetChannel($channel);

        config()->set('sso.logging.channel', $channel);

        return $this->logCaptures[$channel] = $handler;
    }

    /**
     * What was logged to the captured channel named, or to every captured
     * channel, in the order each channel received it.
     *
     * @param  ?string  $channel
     * @return list<array{channel: string, level: string, message: string, context: array<array-key, mixed>}>
     */
    protected function capturedLogRecords(?string $channel = null): array
    {
        $records = [];

        foreach ($this->logCaptures as $name => $handler) {

            if ($channel !== null && $name !== $channel) {
                continue;
            }

            foreach ($handler->getRecords() as $record) {
                $records[] = self::describeLogRecord($name, $record);
            }
        }

        return $records;
    }

    /**
     * Assert that no captured record's message or context contains any of the
     * needles. The context is searched JSON-encoded, with slashes and Unicode
     * left unescaped, and value by value, so a needle is found however it was
     * nested.
     *
     * @param  string  ...$needles
     * @return void
     */
    protected function assertNothingLoggedContains(string ...$needles): void
    {
        foreach ($needles as $needle) {

            self::assertNotSame('', $needle, 'An empty needle is in every record.');

            foreach ($this->capturedLogRecords() as $record) {

                $message = sprintf('The %s record logged to [%s] contains a value that must never be logged.', $record['level'], $record['channel']);

                self::assertStringNotContainsString($needle, self::logRecordText($record), $message);
            }
        }
    }

    /**
     * Assert that each needle is in some captured record's message or context,
     * so a flow test shows what may be logged was.
     *
     * @param  string  ...$needles
     * @return void
     */
    protected function assertLoggedContains(string ...$needles): void
    {
        $text = implode("\0", array_map(self::logRecordText(...), $this->capturedLogRecords()));

        foreach ($needles as $needle) {
            self::assertStringContainsString($needle, $text);
        }
    }

    /**
     * The record as a test reads it.
     *
     * @param  string  $channel
     * @param  \Monolog\LogRecord  $record
     * @return array{channel: string, level: string, message: string, context: array<array-key, mixed>}
     */
    private static function describeLogRecord(string $channel, LogRecord $record): array
    {
        return [
            'channel' => $channel,
            'level'   => $record->level->toPsrLogLevel(),
            'message' => $record->message,
            'context' => $record->context,
        ];
    }

    /**
     * Everything searchable in the record: its message, its context
     * JSON-encoded, and each scalar value in its context, joined by NUL so a
     * line break in a value is still found.
     *
     * @param  array{channel: string, level: string, message: string, context: array<array-key, mixed>}  $record
     * @return string
     */
    private static function logRecordText(array $record): string
    {
        $values = [];

        array_walk_recursive($record['context'], static function (mixed $value) use (&$values): void {

            if (!is_scalar($value)) {
                return;
            }

            $values[] = (string) $value;
        });

        return implode("\0", [
            $record['message'],
            (string) json_encode($record['context'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR),
            ...$values,
        ]);
    }
}
