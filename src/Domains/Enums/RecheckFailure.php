<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * Why a scheduled check of a verified domain did not confirm it (SSO-3.3,
 * SSO-11.12), as `Events\DomainRecheckFailed` reports it.
 *
 * A missing or changed record suspends linking by the domain at once and starts
 * the grace period after which it lapses; a failed lookup changes nothing,
 * since the resolver's silence proves nothing either way.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RecheckFailure: string
{
    // The name has no TXT record
    case RECORD_ABSENT = 'record_absent';

    // The name has TXT records, and none of them is the claim's token
    case RECORD_CHANGED = 'record_changed';

    // The resolver could not answer
    case LOOKUP_FAILED = 'lookup_failed';

    /**
     * Whether the failure is evidence that the record has gone, which suspends
     * linking and starts the grace period.
     *
     * @return bool
     */
    public function isRecordGone(): bool
    {
        return $this !== self::LOOKUP_FAILED;
    }
}
