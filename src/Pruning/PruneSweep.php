<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

/**
 * How one kind's turn in a run ended: the rows deleted in the transactions that
 * committed, whether more was eligible when the work cap stopped it, and the
 * exception that stopped it, if one did.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneSweep
{
    /**
     * Constructor.
     *
     * @param  int  $deleted
     * @param  bool  $incomplete
     * @param  ?\Throwable  $failure
     */
    public function __construct(

        /** The rows deleted. */
        public int $deleted,

        /** Whether the work cap stopped the kind with more eligible. */
        public bool $incomplete = false,

        /** The exception that stopped the kind. */
        public ?\Throwable $failure = null,
    ) {}
}
