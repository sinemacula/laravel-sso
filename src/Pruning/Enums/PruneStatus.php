<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning\Enums;

/**
 * How a run of `Pruning\Pruner` ended.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PruneStatus: string
{
    // Every kind reached the end of what was eligible at the run's cutoff
    case COMPLETE = 'complete';

    // A kind reached its work cap with more eligible
    case INCOMPLETE = 'incomplete';

    // A kind stopped on an exception; the batches committed before it stand
    case FAILED = 'failed';
}
