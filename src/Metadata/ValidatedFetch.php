<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;

/**
 * The fetch a proposal's settings came from, stamped on the connection so the
 * stale limit counts from it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ValidatedFetch
{
    /**
     * Constructor.
     *
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  ?\Carbon\CarbonImmutable  $validUntil
     */
    public function __construct(

        /** The moment the fetched document was validated. */
        public CarbonImmutable $validatedAt,

        /** The earliest `validUntil` the document gave, or `null`. */
        public ?CarbonImmutable $validUntil = null,
    ) {}
}
