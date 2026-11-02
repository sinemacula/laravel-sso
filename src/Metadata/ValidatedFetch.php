<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;

/**
 * The fetch a proposal's settings came from (SSO-2.8): the moment the fetched
 * document was validated and its `validUntil`, if any. Given to
 * `Connections\ImportSaver::save()` with what a proposal saves, it is stamped
 * on the connection, so the stale limit counts from that fetch as it does from
 * a refresh's (`MetadataExpiry`). Metadata given as XML came from no fetch, and
 * has none.
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
