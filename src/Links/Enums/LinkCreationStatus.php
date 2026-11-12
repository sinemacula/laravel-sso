<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links\Enums;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a link's creation ended, as the status of a `Links\LinkCreation`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum LinkCreationStatus: string
{
    // The link was made, active, and reported after commit
    case CREATED = 'created';

    // The issuer and subject are already linked in the connection
    case SUBJECT_ALREADY_LINKED = 'subject_already_linked';

    // The identity is at the link limit, unexpired reservations included
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
            self::SUBJECT_ALREADY_LINKED => FailureReason::SUBJECT_ALREADY_LINKED,
            self::LINK_LIMIT_REACHED     => FailureReason::LINK_LIMIT_REACHED,
        };
    }
}
