<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning;

/**
 * One row a scan selected: its primary key and its time as stored, which the
 * scan's next page continues after, and the connection a reservation belongs
 * to. Being selected makes it no more than a candidate: the delete repeats the
 * eligibility, since another server may have changed or deleted it since.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneCandidate
{
    /**
     * Constructor.
     *
     * @param  int|string  $key
     * @param  string  $time
     * @param  ?string  $connectionId
     */
    public function __construct(

        /** The row's primary key: an id, or a counter's key. */
        public int|string $key,

        /** The time the row is judged by, as the database returned it. */
        public string $time,

        /** The connection a reservation belongs to; none for any other kind. */
        public ?string $connectionId = null,
    ) {}
}
