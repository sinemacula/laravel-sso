<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

/**
 * A run of `Pruning\Pruner` in which a kind stopped on an exception, thrown
 * once every kind has had its turn, so a database error still propagates
 * (SSO-11.4) and the report of what committed is not lost. The first kind's
 * exception is chained; the message names the kinds and the classes alone,
 * since another exception's message could carry a value read from the database.
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
     */
    public function __construct(

        /** What the run did before and after the failure. */
        public readonly PruneReport $report,

        // Not promoted: chained, and kept by the base class
        ?\Throwable $previous = null,
    ) {
        $failures = array_map(static fn (string $kind, string $class): string => "{$kind} ({$class})", array_keys($report->failures), $report->failures);

        parent::__construct('The prune stopped on ' . implode(', ', $failures) . '.', 0, $previous);
    }
}
