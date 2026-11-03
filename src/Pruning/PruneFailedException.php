<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

/**
 * A run of `Pruning\Pruner` in which a kind stopped on an exception, or whose
 * summary line the logger refused, thrown once every kind has had its turn, so
 * a database error still propagates (SSO-11.4) and the report of what committed
 * is not lost. The first kind's exception is chained, or the logger's when no
 * kind failed, and the logger's is kept apart as well; the message names the
 * kinds and the classes alone, since another exception's message could carry a
 * value read from the database.
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

        /** What the run did before and after the failure. */
        public readonly PruneReport $report,

        // Not promoted: chained, and kept by the base class
        ?\Throwable $previous = null,

        /** What the logger threw on the run's summary line, if it threw. */
        public readonly ?\Throwable $logFailure = null,
    ) {
        parent::__construct(self::describe($report, $logFailure), 0, $previous);
    }

    /**
     * The message: each kind that stopped, then the logger's failure, each by
     * its exception's class alone.
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
