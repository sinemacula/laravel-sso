<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Where a claim of a domain stands at an instant, judged the same way across
 * the package.
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
     * The name the claim's TXT record is looked up at, such as
     * `_sso-verification.example.com`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return string
     */
    public static function lookupName(Domain $claim): string
    {
        return $claim->record_name . '.' . $claim->domain;
    }

    /**
     * Whether the claim is pending and has expired; one with no expiry has.
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
     * Whether the domain routes discovery at the instant: verified and within
     * any grace period, even before a recheck marks it lapsed.
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
     * Whether the domain allows linking by email at the instant; the age cap
     * stops a stopped scheduler extending it.
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
     * Whether the last successful check is not in the future and no older than
     * the seconds given.
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
