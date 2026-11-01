<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * Where a connection's claim of a domain stands (SSO-3.1 to SSO-3.3): pending
 * until a DNS TXT record proves the tenant controls the domain, verified while
 * it does, and lapsed once its record has gone for longer than the grace
 * period.
 *
 * Only a verified domain routes discovery, marks an email as belonging to its
 * connection, or allows linking by email, and linking needs more than the state
 * (see `Domains\DomainStanding::allowsLinking()`). A lapsed domain can be
 * verified again, and then counts from its new verification time.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DomainState: string
{
    // Claimed, with a token, and waiting for its record until the claim expires
    case PENDING = 'pending';

    // Its record carried the token; verified for this connection and no other
    case VERIFIED = 'verified';

    // It was verified, and its record was missing or changed for longer than
    // the grace period
    case LAPSED = 'lapsed';
}
