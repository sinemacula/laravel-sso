<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

use Illuminate\Log\LogManager;
use Psr\Log\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerTrait;
use Psr\Log\LogLevel;

/**
 * The package's only logger: sanitises every message and redacts every context
 * before Laravel's own processing sees them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SanitizingLogger implements LoggerInterface
{
    use LoggerTrait;

    /** @var list<string> The levels PSR-3 defines. */
    private const array LEVELS = [
        LogLevel::EMERGENCY,
        LogLevel::ALERT,
        LogLevel::CRITICAL,
        LogLevel::ERROR,
        LogLevel::WARNING,
        LogLevel::NOTICE,
        LogLevel::INFO,
        LogLevel::DEBUG,
    ];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Log\LogManager  $logs
     * @param  \SineMacula\Laravel\Sso\Logging\LoggingSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Logging\DiagnosticSanitizer  $sanitizer
     * @param  \SineMacula\Laravel\Sso\Logging\Redactor  $redactor
     */
    public function __construct(

        /** The application's log channels. */
        private LogManager $logs,

        /** The settings the channel is read from. */
        private LoggingSettings $settings,

        /** The sanitiser every message goes through. */
        private DiagnosticSanitizer $sanitizer,

        /** The redactor every context goes through. */
        private Redactor $redactor,
    ) {}

    /**
     * Write to the channel, resolved on each call.
     *
     * @param  mixed  $level
     * @param  string|\Stringable  $message
     * @param  array<array-key, mixed>  $context
     * @return void
     *
     * @throws \Psr\Log\InvalidArgumentException
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function log(mixed $level, string|\Stringable $message, #[\SensitiveParameter] array $context = []): void
    {
        $level = self::level($level);

        $this->logs
            ->channel($this->settings->channel())
            ->log($level, $this->sanitizer->sanitize((string) $message), $this->redactor->redact($context));
    }

    /**
     * The level, refused unless PSR-3 defines it.
     *
     * @param  mixed  $level
     * @return string
     *
     * @throws \Psr\Log\InvalidArgumentException
     */
    private static function level(mixed $level): string
    {
        if (!is_string($level) || !in_array($level, self::LEVELS, true)) {
            throw new InvalidArgumentException('The level must be one of the levels PSR-3 defines.');
        }

        return $level;
    }
}
