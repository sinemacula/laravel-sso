<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Database\RetriedTransaction;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * The scheduled recheck of verified domains that `sso:domains:recheck` runs.
 *
 * Safe on several servers at once: each claim is leased before its lookup, and
 * the lookup runs outside any transaction.
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

    /** @var int Attempts in all at a transaction a deadlock rolled back. */
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
     * @param  \Psr\Log\LoggerInterface  $logger
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

        /** Withdraws what depends on a domain that is suspended or lapses. */
        private DomainWithdrawal $withdrawal,

        /** The sanitising logger a resolver that threw is logged to. */
        private LoggerInterface $logger,
    ) {}

    /**
     * Check every verified claim not changed since the run began, least
     * recently confirmed first.
     *
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\RecheckReport
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function recheckAll(ClientContext $client): RecheckReport
    {
        $startedAt = $this->clock->now();
        $entries   = [];
        $after     = null;

        do {

            $chunk = self::chunkAfter($startedAt, $after);

            foreach ($chunk as $claim) {
                $entries[] = $this->recheck($claim, $client);
            }

            $after = $chunk === [] ? null : $chunk[count($chunk) - 1];
        } while (count($chunk) === self::CHUNK_SIZE);

        return new RecheckReport($entries);
    }

    /**
     * Lease the claim, look its record up unless its grace has run out, and
     * write what the check found.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function recheck(Domain $claim, ClientContext $client): RecheckEntry
    {
        $lease = $this->writeLease($claim);

        if ($lease === null) {
            return RecheckEntry::of($claim, RecheckOutcome::SKIPPED);
        }

        $lookup = $this->lookUp($claim);

        if ($lookup instanceof \Throwable) {
            return $this->resolverThrew($claim, $lease, $lookup);
        }

        return $this->transaction(fn (): RecheckEntry => $this->settle($claim, $lease, $lookup, $client));
    }

    /**
     * The next verified claims by keyset on (`last_successful_check_at`, `id`),
     * leaving out any changed since the run began.
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
     * Lease the claim if it is verified, unchanged and free; when the lease
     * ends, or `null` when not taken.
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
     * The resolver's answer, `null` past the grace period, or what the resolver
     * threw.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return \SineMacula\Laravel\Sso\Domains\DnsLookup|\Throwable|null
     */
    private function lookUp(Domain $claim): DnsLookup|\Throwable|null
    {
        if (self::isPastGrace($claim, $this->clock->now())) {
            return null;
        }

        $name = DomainStanding::lookupName($claim);

        try {
            return $this->resolver->txt($name);
            // The contract forbids throwing, but an application's resolver may
            // @phpstan-ignore catch.neverThrown
        } catch (\Throwable $thrown) {
            return $thrown;
        }
    }

    /**
     * Log the exception's class alone and release this check's lease without
     * stamping the claim, so the next run checks it first.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $lease
     * @param  \Throwable  $thrown
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     *
     * @throws \Throwable
     */
    private function resolverThrew(Domain $claim, CarbonImmutable $lease, \Throwable $thrown): RecheckEntry
    {
        $this->logger->warning('sso.domains.recheck_resolver_threw', ['exception' => $thrown::class]);

        $this->transaction(static function () use ($claim, $lease): void {

            if (self::lockConnection($claim) === null) {
                return;
            }

            Domain::query()->useWritePdo()
                ->whereKey($claim->id)
                ->where('recheck_leased_until', self::stored($lease))
                ->update(['recheck_leased_until' => null]);
        });

        return RecheckEntry::of($claim, RecheckOutcome::RESOLVER_THREW);
    }

    /**
     * Lock the connection then the claim, and write what the lookup found
     * unless the claim changed or this check lost its lease.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $lease
     * @param  ?\SineMacula\Laravel\Sso\Domains\DnsLookup  $lookup
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function settle(Domain $claim, CarbonImmutable $lease, ?DnsLookup $lookup, ClientContext $client): RecheckEntry
    {
        $connection = self::lockConnection($claim);
        $locked     = $connection === null ? null : $this->domains->find($connection, $claim->domain, true);
        $now        = $this->clock->now();

        if ($connection === null || !self::isStill($locked, $claim, $lease, $now)) {
            return RecheckEntry::of($claim, RecheckOutcome::SKIPPED);
        }

        return match (true) {
            self::isPastGrace($locked, $now)               => $this->lapse($connection, $locked, $now, $client),
            $lookup === null                               => RecheckEntry::of($claim, RecheckOutcome::SKIPPED),
            $lookup->isLookupFailed()                      => $this->lookupFailed($connection, $locked, $client),
            $lookup->contains($locked->verification_token) => $this->confirm($connection, $locked, $now, $client),
            default                                        => $this->recordGone($connection, $locked, self::failureOf($lookup), $now, $client),
        };
    }

    /**
     * Move the check time to now and lift any suspension.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $locked
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     *
     * @throws \LogicException
     */
    private function confirm(Connection $connection, Domain $locked, CarbonImmutable $now, ClientContext $client): RecheckEntry
    {
        $wasSuspended = $locked->linking_suspended_at !== null;

        $locked->forceFill([
            'last_successful_check_at' => $now,
            'linking_suspended_at'     => null,
            'lapses_at'                => null,
            'recheck_leased_until'     => null,
        ])->save();

        if ($wasSuspended) {
            $this->events->restored($connection, $locked, $client);
        }

        return RecheckEntry::of($locked, $wasSuspended ? RecheckOutcome::RESTORED : RecheckOutcome::CONFIRMED);
    }

    /**
     * Suspend linking and fix the lapse time, unless already suspended; lapse
     * at once past the grace period.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $locked
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure  $failure
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     *
     * @throws \InvalidArgumentException
     */
    private function recordGone(Connection $connection, Domain $locked, RecheckFailure $failure, CarbonImmutable $now, ClientContext $client): RecheckEntry
    {
        $wasSuspended = $locked->linking_suspended_at !== null;

        if (!$wasSuspended) {

            $lapsesAt = $now->addSeconds($this->settings->recheckGraceSeconds());

            $this->withdrawal->linkingWithdrawn($connection, $locked);

            $locked->forceFill(['linking_suspended_at' => $now, 'lapses_at' => $lapsesAt]);
        }

        $locked->forceFill(['recheck_leased_until' => null])->save();

        $this->events->recheckFailed($connection, $locked, $failure, $client);

        if (self::isPastGrace($locked, $now)) {
            return $this->lapse($connection, $locked, $now, $client);
        }

        return RecheckEntry::of($locked, $wasSuspended ? RecheckOutcome::STILL_FAILING : RecheckOutcome::SUSPENDED);
    }

    /**
     * Release the lease and report the failure; nothing else changes.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $locked
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     */
    private function lookupFailed(Connection $connection, Domain $locked, ClientContext $client): RecheckEntry
    {
        $locked->forceFill(['recheck_leased_until' => null])->save();

        $this->events->recheckFailed($connection, $locked, RecheckFailure::LOOKUP_FAILED, $client);

        return RecheckEntry::of($locked, RecheckOutcome::LOOKUP_FAILED);
    }

    /**
     * Withdraw what depends on the domain, then lapse the claim, freeing the
     * domain for another connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $locked
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     */
    private function lapse(Connection $connection, Domain $locked, CarbonImmutable $now, ClientContext $client): RecheckEntry
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

        $this->events->lapsed($connection, $locked, $client);

        return RecheckEntry::of($locked, RecheckOutcome::LAPSED);
    }

    /**
     * Run the work in one storage transaction, retried on deadlock.
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
        return RetriedTransaction::run(DB::connection(StorageConnection::name()), $work, self::ATTEMPTS);
    }

    /**
     * The claim's connection, locked for update, or `null` when it is gone;
     * deliberately unscoped by tenant.
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
     * Whether the locked row is still the claim looked up: leased by this
     * check, verified, with the same token.
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
     * Whether this check's lease is still on the row and unexpired; a lookup
     * that outlasted it may be staler than another server's write.
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
     * Why a lookup that answered did not confirm the claim.
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
