<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Pruning\Enums;

/**
 * What `Pruning\Pruner` deletes (SSO-11.11), in the order a run gives each its
 * turn. The value names the kind in a report, the command's output and the log.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PruneKind: string
{
    // Authorisation requests past their expiry and the retention
    case AUTHORIZATION_REQUESTS = 'authorization_requests';

    // Handoff codes past their expiry and the retention
    case HANDOFF_CODES = 'handoff_codes';

    // Single-use keys past their expiry
    case SINGLE_USE_KEYS = 'single_use_keys';

    // Link reservations past their expiry
    case RESERVATIONS = 'reservations';

    // Pending domain claims past their expiry
    case PENDING_CLAIMS = 'pending_claims';

    // Rate limit counters whose window has ended
    case RATE_LIMITS = 'rate_limits';
}
