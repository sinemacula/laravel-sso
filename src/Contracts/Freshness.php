<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * Freshness contract (SSO-2.12): asked before each operation that could widen
 * or redirect access, or destroy it, whether the caller authenticated recently
 * enough for it.
 *
 * The package asks with the operation's stable name, its own requirement (a
 * maximum age in seconds configured per operation) and the caller the action is
 * taken for (`Identities\Caller`): the identity and, when the application
 * supplied one, the session. An implementation judges that caller and its
 * session, never the request or job being served, and answers `fresh` only when
 * the caller authenticated no more than that many seconds ago; it answers
 * `stale` otherwise, including for no caller (a scheduled job, a console
 * command) and for a caller it cannot judge, such as one with no session when
 * it judges sessions. The package writes nothing on `stale`.
 *
 * The default refuses every operation, so an application that uses the
 * management helpers binds its own; an adapter to the application's
 * authentication binds it to that freshness check, passing the maximum age on
 * as the caller's requirement. An implementation keeps nothing of one call for
 * the next (SSO-11.2). An error it cannot answer through propagates as a server
 * error; it never answers `fresh` when it cannot tell.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Freshness
{
    /**
     * Whether the caller authenticated within the maximum age for the
     * operation; `stale` for no caller.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     */
    public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome;
}
