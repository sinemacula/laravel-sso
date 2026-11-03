<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys\Enums;

/**
 * What a run of `Keys\ExpiryReport` did about warning of one key or certificate
 * it lists.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ExpiryNotice: string
{
    // The warning was dispatched by this run, and recorded
    case NOTIFIED = 'notified';

    // A warning of this threshold, or a more urgent one, was dispatched before
    case ALREADY_NOTIFIED = 'already_notified';

    // It is within the window listed, but has reached no threshold
    case NOT_DUE = 'not_due';

    // Another reporter holds it and is sending the warning; if that reporter
    // dies, a later run sends it when the claim runs out
    case CLAIMED = 'claimed';

    // The dispatch threw, so nothing was recorded and a later run sends it
    // again
    case FAILED = 'failed';
}
