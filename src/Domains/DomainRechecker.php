<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * The scheduled recheck of verified domains (SSO-3.3, SSO-11.12), which
 * `sso:domains:recheck` runs: each verified claim's TXT record is looked up
 * again, and the claim is confirmed, suspended, restored or lapsed.
 *
 * - A record that still carries the token moves the last successful check to
 *   now and keeps the verification time.
 * - A record absent or changed suspends linking by the domain at once and fixes
 *   when it lapses, at now plus the grace period read at that moment; while the
 *   grace runs, the domain still routes discovery. A record back within the
 *   grace restores it.
 * - A claim whose grace has run out lapses without a lookup, whatever its
 *   record now holds: only a new verification restores it.
 * - A lookup that failed changes nothing and is reported; it is never read as a
 *   record gone or as a success, so linking by the domain still stops once its
 *   last successful check is older than the linking maximum age.
 *
 * Several servers may run it at once. The verified claims not changed since the
 * run began are read on the write connection in chunks of `CHUNK_SIZE`, by
 * keyset on (`last_successful_check_at`, `id`). Each claim is then leased for
 * `LEASE_SECONDS` by one conditional update, made under its connection's lock
 * and only while the claim is verified, unleased (or its lease has expired) and
 * unchanged since it was selected: a claim another server holds, or has checked
 * meanwhile, is `skipped`. The record is looked up outside any transaction. The
 * result is written in one transaction on the storage connection that locks the
 * connection's row and then the claim, in the order every domain change takes
 * them, and reads again with those locking reads whether the claim is still the
 * one looked up and still under this check's lease: a lookup that outlasted its
 * lease, or whose claim another server has leased since, writes nothing and is
 * `skipped`. Each write goes through the model, releases the lease, and reports
 * through `Administration\DomainEvents` after the write; a skip or an exception
 * leaves the lease to expire.
 *
 * Whatever stops linking by a domain (a suspension or a lapse) calls
 * `DomainWithdrawal::linkingWithdrawn()` under both locks, before the write. A
 * lapse runs in that one transaction, which linking by a verified domain
 * extends to void the domain's open link reservations.
 *
 * It asks no freshness and takes no rate-limit attempt: it is a system job,
 * with no caller and no tenant. A database error or a resolver that throws
 * propagates (SSO-11.4) and stops the run. It holds the finder, the resolver,
 * the settings, the clock, the reporter and the withdrawal, none of which keeps
 * anything of one run for the next (SSO-11.2); resolve it per run.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DomainRechecker
{
    /** @var int How long a server holds a claim it is checking, in seconds. */
    public const int LEASE_SECONDS = 300;

    /** @var int How many claims are read at a time. */
    public const int CHUNK_SIZE = 100;

    /** @var int How many times a transaction a deadlock rolled back is tried in all. */
    private const int ATTEMPTS = 3;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainFinder  $domains
     * @param  \SineMacula\Laravel\Sso\Contracts\DnsResolver  $resolver
     * @param  \SineMacula\Laravel\Sso\Domains\DomainSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Administration\DomainEvents  $events
     * @param  \SineMacula\Laravel\Sso\Domains\DomainWithdrawal  $withdrawal
     */
    public function __construct(

        /** Finds a claim again under its connection's lock, on the write connection. */
        private DomainFinder $domains,

        /** Looks each TXT record up. */
        private DnsResolver $resolver,

        /** The grace period. */
        private DomainSettings $settings,

        /** The clock every time is read from. */
        private Clock $clock,

        /** Reports each change, inside its transaction. */
        private DomainEvents $events,

        /** Withdraws what depends on linking by a domain that is suspended or lapses. */
        private DomainWithdrawal $withdrawal,
    ) {}

    /**
     * Check every verified claim not changed since the run began, least
     * recently confirmed first.
     *
     * @return \SineMacula\Laravel\Sso\Domains\RecheckReport
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function recheckAll(): RecheckReport
    {
        $startedAt = $this->clock->now();
        $entries   = [];
        $after     = null;

        do {

            $chunk = self::chunkAfter($startedAt, $after);

            foreach ($chunk as $claim) {
                $entries[] = $this->recheck($claim);
            }

            $after = $chunk === [] ? null : $chunk[count($chunk) - 1];
        } while (count($chunk) === self::CHUNK_SIZE);

        return new RecheckReport($entries);
    }

    /**
     * Check the verified claim, as it was read: lease it, look its record up
     * unless its grace has run out, and write what the check found.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function recheck(Domain $claim): RecheckEntry
    {
        $lease = $this->writeLease($claim);

        if ($lease === null) {
            return RecheckEntry::of($claim, RecheckOutcome::SKIPPED);
        }

        $lookup = self::isPastGrace($claim, $this->clock->now()) ? null : $this->resolver->txt(DomainStanding::lookupName($claim));

        return $this->transaction(fn (): RecheckEntry => $this->settle($claim, $lease, $lookup));
    }

    /**
     * The next verified claims after the one given, in order of their last
     * successful check and id, leaving out any changed since the run began.
     *
     * @param  \Carbon\CarbonImmutable  $startedAt
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $after
     * @return list<\SineMacula\Laravel\Sso\Models\Domain>
     *
     * @throws \LogicException
     */
    private static function chunkAfter(CarbonImmutable $startedAt, ?Domain $after): array
    {
        $query = Domain::query()->useWritePdo()
            ->where('state', DomainState::VERIFIED->value)
            ->whereNotNull('last_successful_check_at')
            ->where('updated_at', '<', self::stored($startedAt));

        if ($after !== null) {

            $checked = self::stored($after->last_successful_check_at ?? throw new \LogicException('A verified claim has a successful check.'));
            $id      = $after->id;

            $query->where(static function (Builder $keyset) use ($checked, $id): void {
                $keyset->where('last_successful_check_at', '>', $checked)
                    ->orWhere(static function (Builder $tie) use ($checked, $id): void {
                        $tie->where('last_successful_check_at', $checked)->where('id', '>', $id);
                    });
            });
        }

        return array_values($query->orderBy('last_successful_check_at')->orderBy('id')->limit(self::CHUNK_SIZE)->get()->all());
    }

    /**
     * Take the claim's lease, under its connection's lock: only while it is
     * verified, unchanged since it was read, and not leased, or leased no
     * longer. Answers when the lease taken runs out, or `null` when it was not
     * taken.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Throwable
     */
    private function writeLease(Domain $claim): ?CarbonImmutable
    {
        return $this->transaction(function () use ($claim): ?CarbonImmutable {

            if (self::lockConnection($claim) === null) {
                return null;
            }

            $now   = $this->clock->now();
            $at    = self::stored($now);
            $until = $now->addSeconds(self::LEASE_SECONDS);

            $leased = Domain::query()->useWritePdo()
                ->whereKey($claim->id)
                ->where('state', DomainState::VERIFIED->value)
                ->where('updated_at', self::stored($claim->updated_at))
                ->where(static function (Builder $free) use ($at): void {
                    $free->whereNull('recheck_leased_until')->orWhere('recheck_leased_until', '<=', $at);
                })
                ->update(['recheck_leased_until' => self::stored($until)]);

            return $leased === 1 ? $until : null;
        });
    }

    /**
     * Inside the transaction: lock the claim's connection, then the claim, and
     * write what the lookup found, unless the claim went, changed or is no
     * longer verified meanwhile, or this check's lease ran out or was taken
     * over. Without a lookup, the claim's grace had run out when it was read.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $lease
     * @param  ?\SineMacula\Laravel\Sso\Domains\DnsLookup  $lookup
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function settle(Domain $claim, CarbonImmutable $lease, ?DnsLookup $lookup): RecheckEntry
    {
        $connection = self::lockConnection($claim);
        $locked     = $connection === null ? null : $this->domains->find($connection, $claim->domain, true);
        $now        = $this->clock->now();

        if ($connection === null || !self::isStill($locked, $claim, $lease, $now)) {
            return RecheckEntry::of($claim, RecheckOutcome::SKIPPED);
        }

        return match (true) {
            self::isPastGrace($locked, $now)               => $this->lapse($connection, $locked, $now),
            $lookup === null                               => RecheckEntry::of($claim, RecheckOutcome::SKIPPED),
            $lookup->isLookupFailed()                      => $this->lookupFailed($connection, $locked),
            $lookup->contains($locked->verification_token) => $this->confirm($connection, $locked, $now),
            default                                        => $this->recordGone($connection, $locked, self::failureOf($lookup), $now),
        };
    }

    /**
     * Its record carries the token: the check time moves to now, the
     * verification time is kept, and a suspension is lifted.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $locked
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     *
     * @throws \LogicException
     */
    private function confirm(Connection $connection, Domain $locked, CarbonImmutable $now): RecheckEntry
    {
        $wasSuspended = $locked->linking_suspended_at !== null;

        $locked->forceFill([
            'last_successful_check_at' => $now,
            'linking_suspended_at'     => null,
            'lapses_at'                => null,
            'recheck_leased_until'     => null,
        ])->save();

        if ($wasSuspended) {
            $this->events->restored($connection, $locked);
        }

        return RecheckEntry::of($locked, $wasSuspended ? RecheckOutcome::RESTORED : RecheckOutcome::CONFIRMED);
    }

    /**
     * Its record is absent or changed: linking by it is suspended from now,
     * after what depends on it is withdrawn, and it lapses at the end of the
     * grace period, fixed now; a claim already suspended keeps both times. It
     * lapses at once when the grace has run out.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $locked
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure  $failure
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     *
     * @throws \InvalidArgumentException
     */
    private function recordGone(Connection $connection, Domain $locked, RecheckFailure $failure, CarbonImmutable $now): RecheckEntry
    {
        $wasSuspended = $locked->linking_suspended_at !== null;

        if (!$wasSuspended) {

            $lapsesAt = $now->addSeconds($this->settings->recheckGraceSeconds());

            $this->withdrawal->linkingWithdrawn($connection, $locked);

            $locked->forceFill(['linking_suspended_at' => $now, 'lapses_at' => $lapsesAt]);
        }

        $locked->forceFill(['recheck_leased_until' => null])->save();

        $this->events->recheckFailed($connection, $locked, $failure);

        if (self::isPastGrace($locked, $now)) {
            return $this->lapse($connection, $locked, $now);
        }

        return RecheckEntry::of($locked, $wasSuspended ? RecheckOutcome::STILL_FAILING : RecheckOutcome::SUSPENDED);
    }

    /**
     * The resolver could not answer: nothing about the claim changes but its
     * lease, and the failure is reported with the lapse time as it stands.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $locked
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     */
    private function lookupFailed(Connection $connection, Domain $locked): RecheckEntry
    {
        $locked->forceFill(['recheck_leased_until' => null])->save();

        $this->events->recheckFailed($connection, $locked, RecheckFailure::LOOKUP_FAILED);

        return RecheckEntry::of($locked, RecheckOutcome::LOOKUP_FAILED);
    }

    /**
     * The grace period has run out: what depends on linking by the domain is
     * withdrawn, then the claim lapses, freeing the domain for another
     * connection and keeping its last successful check for display. Called
     * inside the transaction that holds the connection's and the claim's locks.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $locked
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     */
    private function lapse(Connection $connection, Domain $locked, CarbonImmutable $now): RecheckEntry
    {
        $this->withdrawal->linkingWithdrawn($connection, $locked);

        $locked->forceFill([
            'state'                => DomainState::LAPSED,
            'verified_domain'      => null,
            'verified_at'          => null,
            'lapsed_at'            => $now,
            'lapses_at'            => null,
            'linking_suspended_at' => null,
            'recheck_leased_until' => null,
        ])->save();

        $this->events->lapsed($connection, $locked);

        return RecheckEntry::of($locked, RecheckOutcome::LAPSED);
    }

    /**
     * Run the work in one transaction on the storage connection, retried when a
     * deadlock rolled back the outermost transaction.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $work
     * @return TResult
     *
     * @throws \Throwable
     */
    private function transaction(\Closure $work): mixed
    {
        return DB::connection(StorageConnection::name())->transaction($work, self::ATTEMPTS);
    }

    /**
     * The claim's connection, locked for update until the transaction ends, or
     * `null` when it is gone. A recheck is not scoped to a tenant: it reaches
     * every connection's claims.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private static function lockConnection(Domain $claim): ?Connection
    {
        $found = Connection::query()->useWritePdo()->whereKey($claim->connection_id)->lockForUpdate()->first();

        return $found?->id === $claim->connection_id ? $found : null;
    }

    /**
     * Whether the row read again under the lock is still the claim that was
     * read and looked up: the same row, still under this check's lease,
     * verified, with the same token.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $locked
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $lease
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @phpstan-assert-if-true \SineMacula\Laravel\Sso\Models\Domain $locked
     */
    private static function isStill(?Domain $locked, Domain $claim, CarbonImmutable $lease, CarbonImmutable $now): bool
    {
        if ($locked === null || $locked->id !== $claim->id) {
            return false;
        }

        if (!self::holdsLease($locked, $lease, $now)) {
            return false;
        }

        return $locked->state === DomainState::VERIFIED && ConstantTime::equals($locked->verification_token, $claim->verification_token);
    }

    /**
     * Whether the row read again under the lock still carries the lease this
     * check took, and it has not run out: a lookup that outlasted it may be
     * older than what a server that took the claim over has since written.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $locked
     * @param  \Carbon\CarbonImmutable  $lease
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    private static function holdsLease(Domain $locked, CarbonImmutable $lease, CarbonImmutable $now): bool
    {
        $held = $locked->recheck_leased_until;

        if ($held === null || $lease <= $now) {
            return false;
        }

        return self::stored($held) === self::stored($lease);
    }

    /**
     * Whether the claim's grace period has run out by the instant.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    private static function isPastGrace(Domain $claim, CarbonImmutable $now): bool
    {
        return $claim->lapses_at !== null && $claim->lapses_at <= $now;
    }

    /**
     * Why a lookup that answered did not confirm the claim: no record, or none
     * that is the token.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DnsLookup  $lookup
     * @return \SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure
     */
    private static function failureOf(DnsLookup $lookup): RecheckFailure
    {
        return $lookup->isAbsent() ? RecheckFailure::RECORD_ABSENT : RecheckFailure::RECORD_CHANGED;
    }

    /**
     * The instant as the domains table stores and compares it.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     * @return string
     */
    private static function stored(CarbonImmutable $instant): string
    {
        return UtcDateTime::format(new Domain, $instant);
    }
}
