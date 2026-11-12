<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * What a TXT lookup through the `Contracts\DnsResolver` answered.
 *
 * `lookup_failed` proves nothing either way, so it is never read as `absent`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DnsLookupStatus: string
{
    // The name has at least one TXT record
    case FOUND = 'found';

    // The name has no TXT record, or does not exist
    case ABSENT = 'absent';

    // The resolver could not answer: a timeout, a server failure, a refusal
    case LOOKUP_FAILED = 'lookup_failed';
}
