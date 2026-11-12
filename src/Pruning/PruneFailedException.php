<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

/**
 * A prune run in which a kind or the summary log line failed; holds the report.
 *
 * The message names exception classes alone, since a message could carry a
 * stored value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PruneFailedException extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneReport  $report
     * @param  ?\Throwable  $previous
     * @param  ?\Throwable  $logFailure
     */
    public function __construct(

        /** What the run committed. */
        public readonly PruneReport $report,

        // Not promoted: chained, and kept by the base class
        ?\Throwable $previous = null,

        /** What the logger threw on the run's summary line, if it threw. */
        public readonly ?\Throwable $logFailure = null,
    ) {
        parent::__construct(self::describe($report, $logFailure), 0, $previous);
    }

    /**
     * The message, naming each failure by its exception class.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\PruneReport  $report
     * @param  ?\Throwable  $logFailure
     * @return string
     */
    private static function describe(PruneReport $report, ?\Throwable $logFailure): string
    {
        $failures = array_map(static fn (string $kind, string $class): string => "{$kind} ({$class})", array_keys($report->failures), $report->failures);
        $message  = $failures === [] ? 'The prune finished' : 'The prune stopped on ' . implode(', ', $failures);

        return $message . ($logFailure === null ? '.' : sprintf(', and its log line failed (%s).', $logFailure::class));
    }
}
