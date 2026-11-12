<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

/**
 * How one kind's turn in a prune run ended.
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
