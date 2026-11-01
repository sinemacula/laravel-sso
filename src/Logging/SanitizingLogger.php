<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Logging;

use Illuminate\Log\LogManager;
use Psr\Log\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerTrait;
use Psr\Log\LogLevel;

/**
 * The one logger the package writes through (SSO-5.7, SSO-9.8, SSO-11.9): a
 * PSR-3 logger that sanitises every message as a diagnostic, redacts every
 * context, and writes to the channel `sso.logging.channel` names, or to
 * Laravel's default channel when it names none.
 *
 * The channel is resolved on each call, so a change to the setting is seen by
 * the next call and nothing of one request or job is kept for the next
 * (SSO-11.2). A level that is not one of PSR-3's is refused with PSR-3's
 * `InvalidArgumentException`. Laravel's own processing of the record (shared
 * context, placeholders a channel replaces) happens after redaction, on what
 * this logger passes on.
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
     * Sanitise the message, redact the context and write both to the configured
     * channel at the level given.
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
     * The level, when it is one PSR-3 defines.
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
