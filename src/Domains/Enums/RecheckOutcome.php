<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * How the scheduled check of one verified domain ended (SSO-3.3, SSO-11.12), as
 * a `Domains\RecheckEntry` reports it.
 *
 * Two outcomes confirm the domain, one of them after its record had gone; four
 * are failures: its record went and linking by it was suspended, its record is
 * still gone within the grace period, it lapsed at the end of the grace period,
 * or the lookup failed, which changes nothing. `skipped` means this run left
 * the claim alone: another server held its lease, or it changed, was removed or
 * lost its connection while it was being checked.
 *
 * Backed, and stable once released: a value is never renamed or reused.
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

    // Its record carries the token again within the grace period; linking by it
    // resumes and it no longer lapses
    case RESTORED = 'restored';

    // Its record is absent or changed; linking by it is suspended from now and
    // it lapses at the end of the grace period
    case SUSPENDED = 'suspended';

    // Its record is still absent or changed, within the grace period
    case STILL_FAILING = 'still_failing';

    // The grace period ran out; it is no longer verified
    case LAPSED = 'lapsed';

    // The resolver could not answer; nothing changed
    case LOOKUP_FAILED = 'lookup_failed';

    // This run left it alone: leased by another server, or changed meanwhile
    case SKIPPED = 'skipped';

    /**
     * Whether the outcome is a failure of the domain's check: a record gone, a
     * lapse or a lookup that failed.
     *
     * @return bool
     */
    public function isFailure(): bool
    {
        return match ($this) {
            self::SUSPENDED, self::STILL_FAILING, self::LAPSED, self::LOOKUP_FAILED => true,
            default                                                                 => false,
        };
    }
}
