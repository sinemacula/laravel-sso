<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * What a TXT lookup through the `Contracts\DnsResolver` answered (SSO-3.2,
 * SSO-3.3, decision D3): records found at the name, none there, or no answer at
 * all.
 *
 * `lookup_failed` is never read as `absent` or as a record: a resolver that
 * could not answer verifies nothing, and a recheck it fails changes nothing.
 *
 * Backed, and stable once released: a value is never renamed or reused.
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
