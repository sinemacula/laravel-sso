<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * Why a scheduled check of a verified domain did not confirm it.
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
     * Whether the record has gone, which suspends linking and starts the grace
     * period; a failed lookup proves nothing.
     *
     * @return bool
     */
    public function isRecordGone(): bool
    {
        return $this !== self::LOOKUP_FAILED;
    }
}
