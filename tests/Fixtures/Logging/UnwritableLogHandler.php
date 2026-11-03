<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Logging;

use Monolog\Handler\AbstractProcessingHandler;
use Monolog\Logger;
use Monolog\LogRecord;

/**
 * A log destination that cannot be written: every record throws the
 * `UnexpectedValueException` Monolog's stream handler throws when its file
 * cannot be opened. It counts every record that reached it, so a test can show
 * the line was attempted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnwritableLogHandler extends AbstractProcessingHandler
{
    /** @var string The channel the package's logging is pointed at. */
    public const string CHANNEL = 'sso_unwritable';

    /** @var int How many records have reached the handler. */
    public int $attempts = 0;

    /**
     * Configure the channel, backed by a new handler, point the package's
     * logging at it, and answer the handler.
     *
     * @return self
     */
    public static function configure(): self
    {
        $handler = new self;

        config()->set('logging.channels.' . self::CHANNEL, [
            'driver' => 'custom',
            'via'    => static fn (): Logger => new Logger(self::CHANNEL, [$handler]),
        ]);

        /** @var \Illuminate\Log\LogManager $logs */
        $logs = app('log');
        $logs->forgetChannel(self::CHANNEL);

        config()->set('sso.logging.channel', self::CHANNEL);

        return $handler;
    }

    /**
     * Fail to write the record.
     *
     * @param  \Monolog\LogRecord  $record
     * @return never
     *
     * @throws \UnexpectedValueException
     */
    #[\Override]
    protected function write(LogRecord $record): never
    {
        unset($record);

        $this->attempts++;

        throw new \UnexpectedValueException('The log stream could not be opened.');
    }
}
