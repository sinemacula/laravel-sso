<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links\Enums;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a link's creation ended (SSO-8.4): the status of a `Links\LinkCreation`.
 * `created` names a link made and reported; the two refusals name a link not
 * made, with nothing written or reported, each with the failure reason it
 * carries.
 *
 * Backed, and stable once released: a value is never renamed or reused.
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

    // The issuer and subject are already linked in the connection, to this
    // identity or another; uniqueness is not configurable
    case SUBJECT_ALREADY_LINKED = 'subject_already_linked';

    // The identity holds as many links in the connection as the link limit
    // contract allows, active and unexpired reserved ones together
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
