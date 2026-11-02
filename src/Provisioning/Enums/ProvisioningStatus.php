<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Provisioning\Enums;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a call of the provisioning helper ended (SSO-8.6): the status of a
 * `Provisioning\ProvisioningResult`. `created` names a link made, whose event
 * waits for the listener's outer commit; every other names a refusal, which
 * wrote nothing, with the failure reason it carries. A listener rolls its own
 * transaction back on a refusal, and the final continuation then finishes the
 * completion against what the link resolves to.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ProvisioningStatus: string
{
    // The link was made, active, with provisioning as its origin
    case CREATED = 'created';

    // The grant is not this dispatch's, is used or closed, or is bound to
    // another result object
    case GRANT_INVALID = 'grant_invalid';

    // The connection is no longer usable, what was fetched for it has expired,
    // or the request is no longer consumed, unfinished, unvoided and of the
    // connection's trust version
    case REQUEST_UNAVAILABLE = 'request_unavailable';

    // The verified response's deadline has passed
    case EXPIRED = 'expired';

    // The subject is held in the connection: linked to this identity or
    // another, suspended, or reserved by another flow
    case SUBJECT_ALREADY_LINKED = 'subject_already_linked';

    // The identity holds as many links in the connection as it may
    case LINK_LIMIT_REACHED = 'link_limit_reached';

    /**
     * The failure reason of a refusal, or `null` for `created`.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public function reason(): ?FailureReason
    {
        return match ($this) {
            self::CREATED                => null,
            self::GRANT_INVALID          => FailureReason::PROVISIONING_GRANT_INVALID,
            self::REQUEST_UNAVAILABLE    => FailureReason::CONNECTION_UNAVAILABLE,
            self::EXPIRED                => FailureReason::REQUEST_EXPIRED,
            self::SUBJECT_ALREADY_LINKED => FailureReason::SUBJECT_ALREADY_LINKED,
            self::LINK_LIMIT_REACHED     => FailureReason::LINK_LIMIT_REACHED,
        };
    }
}
