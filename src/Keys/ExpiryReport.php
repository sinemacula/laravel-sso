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
 * Lists every key and certificate whose validity ends within a window or has
 * ended, and warns of those that have reached a threshold.
 *
 * Call outside any transaction on the storage connection.
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
     * Warn of every key that has reached a threshold, and hand the callback
     * each one ending within the days given, or the largest threshold.
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
     * The keys of the page whose connection still exists, read in one query.
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
     * The next page of keys ending by the end of the window, by keyset after
     * the key given, leaving out a retiring key whose overlap has ended.
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
     * What this run does about warning of the key, checking the marker before
     * any lock; `null` when it stopped being reportable since it was read.
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
