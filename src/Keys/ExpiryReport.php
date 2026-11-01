<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;

/**
 * Reports every key and certificate, of any connection, whose validity ends
 * within the warning or has already ended (SSO-2.6, SSO-11.12): each is
 * returned as a `Keys\KeySummary` and reported with one
 * `Events\KeyNearingExpiry` through `Administration\AdministrationEvents`, with
 * no acting identity, since the report runs on a schedule rather than for an
 * administrator.
 *
 * The window is `sso.keys.expiry_warning_days` (`KeySettings`) unless a number
 * of days is given, 1 to 365, each a day of 86400 seconds counted from the
 * clock's now. A key or certificate is reported when its `not_after` is at or
 * before the end of the window, an expired one included; one with no end of
 * validity never is, and neither is a retiring key whose overlap has ended,
 * which decryption no longer accepts. The rows are read on the write
 * connection, ordered by `not_after` and then by id, and their connections
 * loaded there in one query; a row whose connection is gone is skipped.
 *
 * It reports, and changes and enforces nothing: trust comes from the configured
 * certificate, never its dates, and an expired one is still trusted (SSO-2.6).
 * Outside a transaction each event is dispatched at once; inside one on the
 * storage connection, once it commits. The scheduled command
 * `sso:keys:expiring`, and the de-duplication that keeps it from reporting the
 * same key on every run, arrive with BL-70; until then the application calls
 * `report()` from its own schedule.
 *
 * It holds the reporter, the key settings and the clock, none of which keeps
 * anything of one call for the next (SSO-11.2).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExpiryReport
{
    /** @var int The least number of days a report may look ahead. */
    public const int MIN_DAYS = 1;

    /** @var int The greatest number of days a report may look ahead. */
    public const int MAX_DAYS = 365;

    /** @var int The seconds in a day of the window. */
    private const int SECONDS_PER_DAY = 86400;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $events
     * @param  \SineMacula\Laravel\Sso\Keys\KeySettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Reports each key or certificate nearing expiry. */
        private AdministrationEvents $events,

        /** The configured warning, read on each call. */
        private KeySettings $settings,

        /** The clock the window is counted from. */
        private Clock $clock,
    ) {}

    /**
     * Report every key and certificate whose validity ends within the days
     * given, or the configured warning when none are, or has already ended,
     * ordered by the end of validity and then by id.
     *
     * @param  ?int  $withinDays
     * @return list<\SineMacula\Laravel\Sso\Keys\KeySummary>
     *
     * @throws \InvalidArgumentException
     */
    public function report(?int $withinDays = null): array
    {
        $days = $withinDays ?? $this->settings->expiryWarningDays();

        if ($days < self::MIN_DAYS || $days > self::MAX_DAYS) {
            throw new \InvalidArgumentException(sprintf('An expiry report looks %d to %d days ahead.', self::MIN_DAYS, self::MAX_DAYS));
        }

        $now  = $this->clock->now();
        $keys = self::nearing($now->addSeconds($days * self::SECONDS_PER_DAY), $now);

        if ($keys === []) {
            return [];
        }

        $connections = Connection::query()
            ->useWritePdo()
            ->whereKey(array_values(array_unique(array_map(static fn (ConnectionKey $key): string => $key->connection_id, $keys))))
            ->get()
            ->keyBy('id')
            ->all();

        $summaries = [];

        foreach ($keys as $key) {

            $connection = $connections[$key->connection_id] ?? null;

            if (!$connection instanceof Connection) {
                continue;
            }

            $this->events->keyNearingExpiry($connection, $key);

            $summaries[] = KeySummary::of($key);
        }

        return $summaries;
    }

    /**
     * Every key and certificate whose validity ends at or before the end of the
     * window, but for a retiring key whose overlap ended by now, read on the
     * write connection, ordered by the end of validity and then by id.
     *
     * @param  \DateTimeInterface  $until
     * @param  \DateTimeInterface  $now
     * @return list<\SineMacula\Laravel\Sso\Models\ConnectionKey>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function nearing(\DateTimeInterface $until, \DateTimeInterface $now): array
    {
        $model  = new ConnectionKey;
        $cutoff = UtcDateTime::format($model, $now);

        return array_values(ConnectionKey::query()
            ->useWritePdo()
            ->whereNotNull('not_after')
            ->where('not_after', '<=', UtcDateTime::format($model, $until))
            ->where(static function (Builder $query) use ($cutoff): void {
                $query->whereNull('state')
                    ->orWhere('state', '!=', KeyState::RETIRING->value)
                    ->orWhereNull('retiring_until')
                    ->orWhere('retiring_until', '>', $cutoff);
            })
            ->orderBy('not_after')
            ->orderBy('id')
            ->get()
            ->all());
    }
}
