<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;

/**
 * Sends one key's expiry warning at least once (SSO-2.6, SSO-11.12): a
 * duplicate is possible and a silent loss is not.
 *
 * 1. A short transaction locks the connection, then the key, in the order every
 *    key change takes them, and reads again whether the key is still
 *    reportable, which threshold it has reached, whether that is more urgent
 *    than the last it was warned of, and whether another reporter holds it. It
 *    then writes a claim until now plus `expiry_claim_seconds`, which only
 *    limits how many reporters send at once.
 * 2. With the transaction closed, the event is dispatched.
 * 3. Only then is the marker recorded, one statement that only ever makes it
 *    more urgent, and the claim released, if it is still this reporter's.
 *
 * A process that dies after step 1 leaves the claim to run out, and the next
 * run sends the warning; one that dies after step 2 has sent a warning a later
 * run sends again. A dispatch that throws, which may have reached some
 * listeners, releases the claim, records nothing, and is reported as `failed`,
 * logged by its exception's class alone. A key retired or removed after its
 * claim is warned of once more at most, and the marker's statements then touch
 * no row.
 *
 * It holds the reporter, the settings, the clock and the logger, none of which
 * keeps anything of one key for the next (SSO-11.2). A database error
 * propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExpiryNotifier
{
    /** @var int How many times a claim a deadlock rolled back is tried in all. */
    private const int ATTEMPTS = 3;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $events
     * @param  \SineMacula\Laravel\Sso\Keys\KeySettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \Psr\Log\LoggerInterface  $logger
     */
    public function __construct(

        /** Reports the warning. */
        private AdministrationEvents $events,

        /** The thresholds and how long a claim lasts, read on each call. */
        private KeySettings $settings,

        /** The clock every time is read from. */
        private Clock $clock,

        /** The sanitising logger a dispatch that threw is logged to. */
        private LoggerInterface $logger,
    ) {}

    /**
     * Warn of the key read unless, under the locks, that is no longer due;
     * `null` means the key is no longer reportable.
     *
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice
     *
     * @throws \Throwable
     */
    public function notify(ConnectionKey $key, ClientContext $client): ?ExpiryNotice
    {
        $claim = $this->claim($key);

        if (!$claim instanceof ExpiryClaim) {
            return $claim;
        }

        try {
            $this->events->keyNearingExpiry($claim->connection, $claim->key, $claim->thresholdDays, $client);
        } catch (\Throwable $exception) {

            self::release($claim);

            $this->logger->warning('sso.keys.expiry_dispatch_failed', ['key_id' => $claim->key->id, 'exception' => $exception::class]);

            return ExpiryNotice::FAILED;
        }

        $this->record($claim);

        return ExpiryNotice::NOTIFIED;
    }

    /**
     * Whether the key may still be reported at the instant: it has an end of
     * validity, and is not a retiring key whose overlap has ended, which
     * decryption no longer accepts.
     *
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  \DateTimeInterface  $now
     * @return bool
     */
    private static function isReportable(ConnectionKey $key, \DateTimeInterface $now): bool
    {
        if ($key->not_after === null || $key->state !== KeyState::RETIRING || $key->retiring_until === null) {
            return $key->not_after !== null;
        }

        return $key->retiring_until > $now;
    }

    /**
     * Why the key takes no claim: it was warned of this threshold or a more
     * urgent one, or another reporter's claim holds; `null` when it takes one.
     *
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @param  int  $thresholdDays
     * @param  \DateTimeInterface  $now
     * @return ?\SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice
     */
    private static function standing(ConnectionKey $key, int $thresholdDays, \DateTimeInterface $now): ?ExpiryNotice
    {
        if ($key->expiry_notified_threshold !== null && $key->expiry_notified_threshold <= $thresholdDays) {
            return ExpiryNotice::ALREADY_NOTIFIED;
        }

        return $key->expiry_claimed_until !== null && $key->expiry_claimed_until > $now ? ExpiryNotice::CLAIMED : null;
    }

    /**
     * The key read again and locked for update until the transaction ends, or
     * `null` when it is gone from the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @return ?\SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private static function lockKey(Connection $connection, ConnectionKey $key): ?ConnectionKey
    {
        return ConnectionKey::query()->useWritePdo()->whereKey($key->id)->where('connection_id', $connection->id)->lockForUpdate()->first();
    }

    /**
     * Release the claim, if it is still this reporter's.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\ExpiryClaim  $claim
     * @return void
     */
    private static function release(ExpiryClaim $claim): void
    {
        ConnectionKey::query()->useWritePdo()
            ->whereKey($claim->key->id)
            ->where('expiry_claimed_until', $claim->until)
            ->update(['expiry_claimed_until' => null]);
    }

    /**
     * In one short transaction, under the connection's and the key's locks,
     * write a claim on the key if it still needs a warning. Answers the claim,
     * the notice that says why not, or `null` when it is no longer reportable.
     *
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @return \SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice|\SineMacula\Laravel\Sso\Keys\ExpiryClaim|null
     *
     * @throws \Throwable
     */
    private function claim(ConnectionKey $key): ExpiryClaim|ExpiryNotice|null
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($key): ExpiryClaim|ExpiryNotice|null {

            $connection = Connection::query()->useWritePdo()->whereKey($key->connection_id)->lockForUpdate()->first();
            $locked     = $connection === null ? null : self::lockKey($connection, $key);
            $now        = $this->clock->now();

            if ($connection === null || $locked === null || !self::isReportable($locked, $now)) {
                return null;
            }

            return $this->claimLocked($connection, $locked, $now);
        }, self::ATTEMPTS);
    }

    /**
     * With both locks held, write the claim, or say why there is none.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $locked
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Sso\Keys\Enums\ExpiryNotice|\SineMacula\Laravel\Sso\Keys\ExpiryClaim
     *
     * @throws \InvalidArgumentException
     */
    private function claimLocked(Connection $connection, ConnectionKey $locked, CarbonImmutable $now): ExpiryClaim|ExpiryNotice
    {
        $threshold = $this->settings->expiryThresholds()->reachedBy($locked->not_after ?? $now, $now);

        if ($threshold === null) {
            return ExpiryNotice::NOT_DUE;
        }

        $notice = self::standing($locked, $threshold, $now);

        if ($notice !== null) {
            return $notice;
        }

        $until = UtcDateTime::format($locked, $now->addSeconds($this->settings->expiryClaimSeconds()));

        ConnectionKey::query()->useWritePdo()->whereKey($locked->id)->update(['expiry_claimed_until' => $until]);

        return new ExpiryClaim($connection, $locked, $threshold, $until);
    }

    /**
     * Record that the warning was dispatched, only ever making the marker more
     * urgent, and release the claim, if it is still this reporter's.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\ExpiryClaim  $claim
     * @return void
     */
    private function record(ExpiryClaim $claim): void
    {
        $threshold = $claim->thresholdDays;

        ConnectionKey::query()->useWritePdo()
            ->whereKey($claim->key->id)
            ->where(static function (Builder $marker) use ($threshold): void {
                $marker->whereNull('expiry_notified_threshold')->orWhere('expiry_notified_threshold', '>', $threshold);
            })
            ->update([
                'expiry_notified_threshold' => $threshold,
                'expiry_notified_at'        => UtcDateTime::format($claim->key, $this->clock->now()),
            ]);

        self::release($claim);
    }
}
