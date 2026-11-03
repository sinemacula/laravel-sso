<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;

/**
 * Freshness contract (SSO-2.12): asked before each operation that could widen
 * or redirect access, or destroy it, whether the caller authenticated recently
 * enough for it.
 *
 * The package asks with the operation's stable name and its own requirement, a
 * maximum age in seconds configured per operation; an implementation answers
 * `fresh` only when the caller of the request or job being served authenticated
 * no more than that many seconds ago, and `stale` otherwise, including when
 * there is no caller it can judge (a queued job, a console command). The
 * package writes nothing on `stale`.
 *
 * The default refuses every operation, so an application that uses the
 * management helpers binds its own; an adapter to the application's
 * authentication binds it to that freshness check, passing the maximum age on
 * as the caller's requirement. An implementation reads the caller from the
 * request or job being served on each call and keeps nothing of one for the
 * next (SSO-11.2). An error it cannot answer through propagates as a server
 * error; it never answers `fresh` when it cannot tell.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Freshness
{
    /**
     * Whether the caller authenticated within the maximum age for the
     * operation.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     */
    public function check(FreshnessOperation $operation, int $maxAgeSeconds): FreshnessOutcome;
}
