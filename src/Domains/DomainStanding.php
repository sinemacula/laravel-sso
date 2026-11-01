<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Where a claim of a domain stands at an instant (SSO-3.1 to SSO-3.3, SSO-8.8),
 * judged the one way every part of the package judges it: the claims helpers,
 * the scheduled rechecks, discovery and linking by a verified domain.
 *
 * - A pending claim has expired at its expiry, or at once when it has none.
 * - A domain routes discovery, and marks an email as belonging to its
 *   connection, while it is verified and before the end of a grace period, even
 *   before a recheck marks it lapsed.
 * - A domain allows linking by email while it routes, linking is not suspended,
 *   and its last successful check is no later than the instant and no older
 *   than the maximum age, which is never more than a day, so a stopped
 *   scheduler cannot extend it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DomainStanding
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The name the claim's TXT record is looked up at: the record name under
     * the domain, `_sso-verification.example.com`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return string
     */
    public static function lookupName(Domain $claim): string
    {
        return $claim->record_name . '.' . $claim->domain;
    }

    /**
     * Whether the claim is pending and has expired by the instant.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    public static function isPendingExpired(Domain $claim, CarbonImmutable $now): bool
    {
        if ($claim->state !== DomainState::PENDING) {
            return false;
        }

        return $claim->pending_expires_at === null || $claim->pending_expires_at <= $now;
    }

    /**
     * Whether the domain routes discovery and marks an email as belonging to
     * its connection at the instant (SSO-3.3, SSO-3.4, SSO-8.1).
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    public static function routes(Domain $claim, CarbonImmutable $now): bool
    {
        if ($claim->state !== DomainState::VERIFIED) {
            return false;
        }

        return $claim->lapses_at === null || $claim->lapses_at > $now;
    }

    /**
     * Whether the domain allows linking by email at the instant (SSO-3.3,
     * SSO-8.8), with a last successful check within the maximum age, capped at
     * a day.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $maxAgeSeconds
     * @return bool
     */
    public static function allowsLinking(Domain $claim, CarbonImmutable $now, int $maxAgeSeconds): bool
    {
        if (!self::routes($claim, $now) || $claim->linking_suspended_at !== null) {
            return false;
        }

        return self::wasCheckedWithin($claim, $now, min($maxAgeSeconds, DomainSettings::MAX_LINKING_AGE_SECONDS));
    }

    /**
     * Whether the claim's last successful check was no later than the instant
     * and no more than the seconds before it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $seconds
     * @return bool
     */
    private static function wasCheckedWithin(Domain $claim, CarbonImmutable $now, int $seconds): bool
    {
        $checked = $claim->last_successful_check_at;

        if ($checked === null || $checked > $now) {
            return false;
        }

        return $checked->addSeconds($seconds) >= $now;
    }
}
