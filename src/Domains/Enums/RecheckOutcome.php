<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains\Enums;

/**
 * How the scheduled check of one verified domain ended (SSO-3.3, SSO-11.12), as
 * a `Domains\RecheckEntry` reports it.
 *
 * Two outcomes confirm the domain, one of them after its record had gone; five
 * are failures: its record went and linking by it was suspended, its record is
 * still gone within the grace period, it lapsed at the end of the grace period,
 * the lookup failed, or the resolver threw; the last two change nothing.
 * `skipped` means this run left the claim alone: another server held its lease,
 * or it changed, was removed or lost its connection while it was being checked.
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

    // The resolver threw instead of answering; nothing changed but the lease,
    // which was released
    case RESOLVER_THREW = 'resolver_threw';

    // This run left it alone: leased by another server, or changed meanwhile
    case SKIPPED = 'skipped';

    /**
     * Whether the outcome is a failure of the domain's check: a record gone, a
     * lapse, a lookup that failed or a resolver that threw.
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
