<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Enums;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * What rechecking a handoff at its redemption came to (SSO-4.6, SSO-8.5,
 * SSO-9.9), as `Handoffs\HandoffRecheck::recheck()` answers it: `passed`, or
 * the first of the checks that refused it, each with the `FailureReason` a
 * redemption refused by it reports (`reason()`).
 *
 * The values are stable once released: a case is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RecheckOutcome: string
{
    // The connection is usable, satisfies its tenant's enforcement, and the
    // result's link resolves to the identity it resolved to at completion
    case PASSED = 'passed';

    // The connection is gone, disabled, or no longer complete or available
    case CONNECTION_UNAVAILABLE = 'connection_unavailable';

    // The tenant's enforcement now requires sign-in through other connections
    case ENFORCEMENT_UNSATISFIED = 'enforcement_unsatisfied';

    // The link was removed, now names another identity, or appeared where there
    // was none at completion
    case LINK_CHANGED = 'link_changed';

    /**
     * The reason a redemption refused by the outcome reports, or `null` when
     * the recheck passed.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public function reason(): ?FailureReason
    {
        return match ($this) {
            self::PASSED                  => null,
            self::CONNECTION_UNAVAILABLE  => FailureReason::CONNECTION_UNAVAILABLE,
            self::ENFORCEMENT_UNSATISFIED => FailureReason::ENFORCEMENT_UNSATISFIED,
            self::LINK_CHANGED            => FailureReason::LINK_CHANGED,
        };
    }
}
