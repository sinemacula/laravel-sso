<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * How the scheduled check of one verified domain ended.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RecheckOutcome: string
{
    // Its record still carries the token; the check time moved
    case CONFIRMED = 'confirmed';

    // Its record carries the token again within the grace period
    case RESTORED = 'restored';

    // Its record is absent or changed; linking is suspended and grace starts
    case SUSPENDED = 'suspended';

    // Its record is still absent or changed, within the grace period
    case STILL_FAILING = 'still_failing';

    // The grace period ran out; it is no longer verified
    case LAPSED = 'lapsed';

    // The resolver could not answer; nothing changed
    case LOOKUP_FAILED = 'lookup_failed';

    // The resolver threw; nothing changed but the lease, which was released
    case RESOLVER_THREW = 'resolver_threw';

    // This run left it alone: leased by another server, or changed meanwhile
    case SKIPPED = 'skipped';

    /**
     * Whether the outcome is a failure of the domain's check.
     *
     * @return bool
     */
    public function isFailure(): bool
    {
        return match ($this) {
            self::SUSPENDED, self::STILL_FAILING, self::LAPSED, self::LOOKUP_FAILED, self::RESOLVER_THREW => true,
            default                                                                                       => false,
        };
    }
}
