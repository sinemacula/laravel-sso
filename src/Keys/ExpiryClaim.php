<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;

/**
 * A reporter's hold on one key while it sends a warning.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExpiryClaim
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  int  $thresholdDays
     * @param  string  $until
     */
    public function __construct(

        /** The connection, as read under its lock. */
        public Connection $connection,

        /** The key, as read under its lock. */
        public ConnectionKey $key,

        /** The threshold to warn of, in days. */
        public int $thresholdDays,

        /** The claim's end as stored; a later claim always ends after it. */
        public string $until,
    ) {}
}
