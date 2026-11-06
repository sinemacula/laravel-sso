<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;

/**
 * Lists every key and certificate, of any connection, whose validity ends
 * within a number of days or has already ended, and warns of those that have
 * reached a threshold (SSO-2.6, SSO-11.12), which `sso:keys:expiring` runs.
 *
 * The window listed is the days given, 1 to 365, or the largest of
 * `sso.keys.expiry_thresholds` (`KeySettings`), each a day of 86400 seconds
 * counted from the clock's now. A key or certificate is listed when its
 * `not_after` is at or before the end of the window, an expired one included; one
 * with no end of validity never is, and neither is a retiring key whose overlap
 * has ended, which decryption no longer accepts. A row whose connection is gone
 * is skipped. What is listed does not depend on what was notified before, so a
 * problem nobody has solved stays visible.
 *
 * The warnings do not depend on the window given: every key that has reached a
 * threshold is looked at, and each gets at most one `Events\KeyNearingExpiry`
 * for the most urgent threshold it has reached, through `ExpiryNotifier`, which
 * sends it at least once. A key warned of that threshold or a more urgent one
 * already takes no lock. Several servers may run it at once: the claim limits
 * how many send, and a duplicate remains possible.
 *
 * The rows are read on the write connection in pages of `PAGE_SIZE`, by keyset
 * on (`not_after`, `id`), never all at once, and each page's connections are
 * loaded in one query. So that a run's memory does not grow with the keys, each
 * entry is handed to the callback given as it is read, ordered by `not_after`
 * and then by id, and the answer holds counts.
 *
 * It reports and enforces nothing: trust comes from the configured certificate,
 * never its dates, and an expired one is still trusted (SSO-2.6). It refuses to
 * run inside a transaction on the storage connection (a `LogicException`),
 * since a warning must be dispatched before it is recorded, which a transaction
 * would hold back until its commit. A database error propagates (SSO-11.4); a
 * dispatch that throws ends that key with `failed` and the run goes on.
 *
 * It takes the client each warning's `Events\KeyNearingExpiry` carries as an
 * `Http\ClientContext` and reads no request: `sso:keys:expiring` passes
 * `new ClientContext(null, null)`. It holds the notifier, the key settings and
 * the clock, none of which keeps anything of one call for the next (SSO-11.2).
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

    /** @var int How many keys are read at a time. */
    public const int PAGE_SIZE = 200;

    /** @var string Why a report refuses to run inside a transaction. */
    private const string IN_TRANSACTION = 'An expiry report runs outside any transaction on the storage connection, since a warning is dispatched before it is recorded.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\ExpiryNotifier  $notifier
     * @param  \SineMacula\Laravel\Sso\Keys\KeySettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Sends each warning due. */
        private ExpiryNotifier $notifier,

        /** The configured thresholds, read on each call. */
        private KeySettings $settings,

        /** The clock the window is counted from. */
        private Clock $clock,
    ) {}

    /**
     * Warn of every key that has reached a threshold, and list those whose
     * validity ends within the days given, or the largest threshold when none
     * are, or has already ended, handing each to the callback, ordered by the
     * end of validity and then by id; each warning's event carries the client.
     *
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?int  $withinDays
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Keys\ExpiringKey): void  $each
     * @return \SineMacula\Laravel\Sso\Keys\ExpiryRun
     *
     * @throws \InvalidArgumentException
     */
    public function report(ClientContext $client, ?int $withinDays = null, ?\Closure $each = null): ExpiryRun
    {
        if ($withinDays !== null && ($withinDays < self::MIN_DAYS || $withinDays > self::MAX_DAYS)) {
            throw new \InvalidArgumentException(sprintf('An expiry report looks %d to %d days ahead.', self::MIN_DAYS, self::MAX_DAYS));
        }

        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        $thresholds = $this->settings->expiryThresholds();
        $largest    = $thresholds->largest();
        $now        = $this->clock->now();
        $listed     = $now->addSeconds(($withinDays ?? $largest) * ExpiryThresholds::SECONDS_PER_DAY);
        $until      = $listed->max($now->addSeconds($largest * ExpiryThresholds::SECONDS_PER_DAY));
        $run        = new ExpiryRun;
        $after      = null;

        do {

            $page = self::pageAfter($after, $until, $now);

            foreach (self::withConnections($page) as $key) {
                $run = $this->reportKey($run, $key, $thresholds, $now, $listed, $client, $each);
            }

            $after = $page === [] ? null : $page[count($page) - 1];
        } while (count($page) === self::PAGE_SIZE);

        return $run;
    }

    /**
     * Those of the page whose connection is still there: the connections are
     * read in one query, on the write connection.
     *
     * @param  array<int, \SineMacula\Laravel\Sso\Models\ConnectionKey>  $page
     * @return array<int, \SineMacula\Laravel\Sso\Models\ConnectionKey>
     */
    private static function withConnections(array $page): array
    {
        $ids = array_unique(array_map(static fn (ConnectionKey $key): string => $key->connection_id, $page));

        if ($ids === []) {
            return [];
        }

        $known = Connection::query()->useWritePdo()->whereKey($ids)->pluck('id')->flip()->all();

        return array_filter($page, static fn (ConnectionKey $key): bool => array_key_exists($key->connection_id, $known));
    }

    /**
     * The next page after the key given: every key and certificate whose
     * validity ends at or before the end of the window, but for a retiring key
     * whose overlap ended by now, read on the write connection, ordered by the
     * end of validity and then by id.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\ConnectionKey  $after
     * @param  \DateTimeInterface  $until
     * @param  \DateTimeInterface  $now
     * @return array<int, \SineMacula\Laravel\Sso\Models\ConnectionKey>
     */
    private static function pageAfter(?ConnectionKey $after, \DateTimeInterface $until, \DateTimeInterface $now): array
    {
        $model  = new ConnectionKey;
        $cutoff = UtcDateTime::format($model, $now);

        $query = ConnectionKey::query()
            ->useWritePdo()
            ->whereNotNull('not_after')
            ->where('not_after', '<=', UtcDateTime::format($model, $until))
            ->where(static function (Builder $query) use ($cutoff): void {
                $query->whereNull('state')
                    ->orWhere('state', '!=', KeyState::RETIRING->value)
                    ->orWhereNull('retiring_until')
                    ->orWhere('retiring_until', '>', $cutoff);
            });

        if ($after?->not_after !== null) {

            $time = UtcDateTime::format($model, $after->not_after);
            $id   = $after->id;

            $query->where(static function (Builder $keyset) use ($time, $id): void {
                $keyset->where('not_after', '>', $time)
                    ->orWhere(static function (Builder $tie) use ($time, $id): void {
                        $tie->where('not_after', $time)->where('id', '>', $id);
                    });
            });
        }

        return $query->orderBy('not_after')->orderBy('id')->limit(self::PAGE_SIZE)->get()->all();
    }

    /**
     * The run with the key counted, and listed when it falls within the window.
     * A key that stopped being reportable since it was read is left out.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\ExpiryRun  $run
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  \SineMacula\Laravel\Sso\Keys\ExpiryThresholds  $thresholds
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Carbon\CarbonImmutable  $listed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Keys\ExpiringKey): void  $each
     * @return \SineMacula\Laravel\Sso\Keys\ExpiryRun
     *
     * @throws \Throwable
     */
    private function reportKey(
        ExpiryRun $run,
        ConnectionKey $key,
        ExpiryThresholds $thresholds,
        CarbonImmutable $now,
        CarbonImmutable $listed,
        ClientContext $client,
        ?\Closure $each,
    ): ExpiryRun {
        $notAfter  = $key->not_after ?? $now;
        $threshold = $thresholds->reachedBy($notAfter, $now);
        $notice    = $this->noticeFor($key, $threshold, $client);

        if ($notice === null) {
            return $run;
        }

        if ($notAfter > $listed) {
            return $run->noting($notice);
        }

        $entry = new ExpiringKey(KeySummary::of($key), $notAfter <= $now, $threshold, $notice);

        $each?->__invoke($entry);

        return $run->noting($notice)->listing($entry);
    }

    /**
     * What this run does about warning of the key, as it was read: nothing for
     * one that has reached no threshold, or was warned of it or a more urgent
     * one already, which takes no lock, and otherwise what the notifier found.
     * `null` means it stopped being reportable since it was read.
     *
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  ?int  $threshold
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice
     *
     * @throws \Throwable
     */
    private function noticeFor(ConnectionKey $key, ?int $threshold, ClientContext $client): ?ExpiryNotice
    {
        if ($threshold === null) {
            return ExpiryNotice::NOT_DUE;
        }

        if ($key->expiry_notified_threshold !== null && $key->expiry_notified_threshold <= $threshold) {
            return ExpiryNotice::ALREADY_NOTIFIED;
        }

        return $this->notifier->notify($key, $client);
    }
}
