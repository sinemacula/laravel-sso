<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Provisioning\Enums;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a provisioning call ended: `created`, or a refusal that wrote nothing.
 *
 * Stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ProvisioningStatus: string
{
    // An active link was made, with provisioning as its origin
    case CREATED = 'created';

    // The grant is not this dispatch's, or is used or closed
    case GRANT_INVALID = 'grant_invalid';

    // A listener bug: not the event's result object; the grant is spent
    case GRANT_WRONG_RESULT = 'grant_wrong_result';

    // The connection or the request no longer stands
    case REQUEST_UNAVAILABLE = 'request_unavailable';

    // The verified response's deadline has passed
    case EXPIRED = 'expired';

    // The subject is linked, suspended or reserved in the connection
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
            self::GRANT_WRONG_RESULT     => FailureReason::PROVISIONING_GRANT_INVALID,
            self::REQUEST_UNAVAILABLE    => FailureReason::CONNECTION_UNAVAILABLE,
            self::EXPIRED                => FailureReason::REQUEST_EXPIRED,
            self::SUBJECT_ALREADY_LINKED => FailureReason::SUBJECT_ALREADY_LINKED,
            self::LINK_LIMIT_REACHED     => FailureReason::LINK_LIMIT_REACHED,
        };
    }
}
