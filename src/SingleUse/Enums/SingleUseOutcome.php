<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\SingleUse\Enums;

/**
 * How recording a key in the single-use store ended (SSO-11.5).
 *
 * Only `recorded` lets a flow proceed. A store that cannot tell (an error, a
 * timeout, an answer it doubts) answers neither: it throws, and the flow is
 * refused as a server error, never passed (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SingleUseOutcome: string
{
    // The key was not held in its namespace, and is now held until its expiry
    case RECORDED = 'recorded';

    // The key is already held in its namespace: a replay, refused
    case SEEN = 'seen';
}
