<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Enums;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * What rechecking a handoff at redemption came to; each refusal maps to the
 * `FailureReason` of the same value.
 *
 * Values are stable: a case is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RecheckOutcome: string
{
    // Every check passed
    case PASSED = 'passed';

    // The connection is gone, disabled, or no longer complete or available
    case CONNECTION_UNAVAILABLE = 'connection_unavailable';

    // The tenant's enforcement now requires sign-in through other connections
    case ENFORCEMENT_UNSATISFIED = 'enforcement_unsatisfied';

    // The link was removed, reassigned, or appeared since completion
    case LINK_CHANGED = 'link_changed';

    // The link is suspended until a confirming `link`
    case LINK_SUSPENDED = 'link_suspended';

    // The principal scope contract could not judge the link's identity
    case PRINCIPAL_SCOPE_UNKNOWN = 'principal_scope_unknown';

    // A live reservation holds the subject, which a `link` waits out
    case LINK_RESERVED = 'link_reserved';

    // The identity may not link through the connection
    case LINK_INELIGIBLE = 'link_ineligible';

    // The caller's authentication depends on the identity's domain links
    case INDEPENDENT_AUTHENTICATION_REQUIRED = 'independent_authentication_required';

    // The caller, or the result's link, is not the flow's identity
    case IDENTITY_MISMATCH = 'identity_mismatch';

    // The subject is linked to another identity, which is never named
    case SUBJECT_ALREADY_LINKED = 'subject_already_linked';

    // The identity holds as many links in the connection as it may
    case LINK_LIMIT_REACHED = 'link_limit_reached';

    // The reservation is gone, expired, or a condition of it no longer holds
    case RESERVATION_INVALID = 'reservation_invalid';

    // The freshness contract answered `stale`
    case FRESHNESS_REQUIRED = 'freshness_required';

    // The session is not active, or not bound to exactly this link
    case SESSION_INELIGIBLE = 'session_ineligible';

    // A `reauthenticate` result states no time the provider authenticated at
    case AUTHENTICATION_EXPIRED = 'authentication_expired';

    /**
     * The reason a redemption refused by the outcome reports, or `null`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public function reason(): ?FailureReason
    {
        return $this === self::PASSED ? null : FailureReason::from($this->value);
    }
}
