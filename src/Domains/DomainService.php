<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Carbon\CarbonImmutable;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * The management helpers of a connection's email domains (SSO-3.1, SSO-3.2,
 * SSO-2.11, SSO-2.12): claim a domain, verify it by its DNS TXT record, remove
 * it, and read one or all of a connection's domains.
 *
 * Every helper is scoped to a tenant (another tenant's connection is
 * `connection_not_found`, exactly as an unknown one) and goes in a fixed order:
 * find the connection, and the claim, on the write connection; validate what
 * was given; ask the freshness contract (`sso.domain.claim`,
 * `sso.domain.verify`, `sso.domain.remove`); for a verification, take one of
 * the connection's domain checks (SSO-11.8) and look the record up through
 * `Contracts\DnsResolver`, outside any transaction; then, in one transaction on
 * the storage connection, read the connection again locked for update, read
 * again what decides the write with locking reads, write, and report through
 * `Administration\DomainEvents`. A refusal at any step writes nothing and
 * reports nothing.
 *
 * - A claim is exact: a domain covers none of its subdomains. It is normalised
 *   (`DomainName`), refused when it is not a host name that could be
 *   registered, when the record name under it would be too long, or when it is
 *   a refused domain or under one (`DomainSettings::refused()`). It is pending
 *   with a new token of `TOKEN_BYTES` random bytes (lower-case hex) from the
 *   system's CSPRNG until it is verified or expires. A domain the connection
 *   claimed already is `duplicate`, unless that claim expired, which is claimed
 *   again with a new token. A domain verified for another connection, of this
 *   tenant or any other, is `domain_unavailable`, which never says whose.
 * - A verification looks up the claim's record name and verifies the domain
 *   only when one of the TXT records there is exactly the claim's token; a
 *   lookup that failed is `domain_lookup_failed`, never read as a missing
 *   record. The domain is then verified for this connection and no other: the
 *   claims of the domain are locked together, so two verifications of it race
 *   to one winner, and the unique index on `verified_domain` refuses any other.
 *   A verified domain is `unchanged`; an expired claim is
 *   `domain_claim_expired`.
 * - A removal deletes the claim in any state, after withdrawing what depends on
 *   linking by it (`DomainWithdrawal`).
 *
 * The locks are always taken in one order: the connection's row, then the
 * claims of one domain in id order. A deadlock MySQL's gap locks can still
 * cause between claims of neighbouring domains is retried, up to `ATTEMPTS`
 * times, when the helper's transaction is the outermost one; inside the
 * application's own, it propagates. A database error, and a resolver or a
 * limiter that throws, propagate (SSO-11.4); an empty or overlong tenant id is
 * an `InvalidArgumentException`.
 *
 * It holds the lookups, the freshness gate, the limiter, the resolver, the
 * settings, the clock, the reporter and the withdrawal, none of which keeps
 * anything of one request for the next (SSO-11.2). Resolve it from the
 * container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DomainService
{
    /** @var int The random bytes in a verification token, written as lower-case hex. */
    public const int TOKEN_BYTES = 32;

    /** @var int How many times a transaction a deadlock rolled back is tried in all. */
    private const int ATTEMPTS = 3;

    /** @var string The domain, as a violation names it. */
    private const string DOMAIN = 'domain';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $connections
     * @param  \SineMacula\Laravel\Sso\Domains\DomainFinder  $domains
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Contracts\DnsResolver  $resolver
     * @param  \SineMacula\Laravel\Sso\Domains\DomainSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Administration\DomainEvents  $events
     * @param  \SineMacula\Laravel\Sso\Domains\DomainWithdrawal  $withdrawal
     */
    public function __construct(

        /** Finds the tenant's connection, on the write connection. */
        private ConnectionFinder $connections,

        /** Finds the claims, on the write connection. */
        private DomainFinder $domains,

        /** Asks the freshness contract before a change is written. */
        private FreshnessGate $freshness,

        /** Counts each verification against the connection's domain checks. */
        private AttemptLimiter $limiter,

        /** Looks the TXT record up. */
        private DnsResolver $resolver,

        /** The record name, the refused domains and the pending expiry. */
        private DomainSettings $settings,

        /** The clock every time is read from. */
        private Clock $clock,

        /** Reports each change, inside its transaction. */
        private DomainEvents $events,

        /** Withdraws what depends on linking by a domain that is removed. */
        private DomainWithdrawal $withdrawal,
    ) {}

    /**
     * Claim the domain for the tenant's connection, pending, with a new
     * verification token.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $domain
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function claim(string $tenantId, string $connectionId, string $domain, ?ActingIdentity $actor = null): DomainResult
    {
        $name       = DomainName::normalize($domain);
        $recordName = $this->settings->recordName();
        $refusal    = $this->claimRefusal($tenantId, $connectionId, $this->claimViolation($domain, $name, $recordName));

        if ($refusal !== null || $name === null) {
            return $refusal ?? DomainResult::invalid([new SettingViolation(self::DOMAIN, ViolationCode::INVALID_FORMAT)]);
        }

        $token  = bin2hex(random_bytes(self::TOKEN_BYTES));
        $expiry = $this->settings->pendingExpirySeconds();

        return $this->change($tenantId, $connectionId, fn (Connection $locked): DomainResult => $this->writeClaim($locked, $name, $recordName, $token, $expiry, $actor));
    }

    /**
     * Verify the tenant's connection's claim of the domain by its TXT record.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $domain
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function verify(string $tenantId, string $connectionId, string $domain, ?ActingIdentity $actor = null): DomainResult
    {
        $found = $this->claimFor($tenantId, $connectionId, $domain);

        if ($found instanceof DomainResult) {
            return $found;
        }

        $token = $found->verification_token;

        return $this->verificationRefusal($found)
            ?? $this->change($tenantId, $connectionId, fn (Connection $locked): DomainResult => $this->writeVerification($locked, $found->domain, $token, $actor));
    }

    /**
     * Remove the tenant's connection's claim of the domain, whatever its state.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $domain
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function remove(string $tenantId, string $connectionId, string $domain, ?ActingIdentity $actor = null): DomainResult
    {
        $found = $this->claimFor($tenantId, $connectionId, $domain);

        if ($found instanceof DomainResult) {
            return $found;
        }

        if (!$this->freshness->check(FreshnessOperation::DOMAIN_REMOVE)->isFresh()) {
            return DomainResult::refused(FailureReason::FRESHNESS_REQUIRED);
        }

        return $this->change($tenantId, $connectionId, fn (Connection $locked): DomainResult => $this->deleteClaim($locked, $found->domain, $actor));
    }

    /**
     * The tenant's connection's claim of the domain, or `null` when it has
     * none.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $domain
     * @return ?\SineMacula\Laravel\Sso\Domains\DomainSummary
     *
     * @throws \InvalidArgumentException
     */
    public function get(string $tenantId, string $connectionId, string $domain): ?DomainSummary
    {
        $found = $this->claimFor($tenantId, $connectionId, $domain);

        return $found instanceof Domain ? DomainSummary::of($found) : null;
    }

    /**
     * Every claim of the tenant's connection, oldest first, or `null` when the
     * tenant has no such connection.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return ?list<\SineMacula\Laravel\Sso\Domains\DomainSummary>
     *
     * @throws \InvalidArgumentException
     */
    public function list(string $tenantId, string $connectionId): ?array
    {
        $connection = $this->connections->find($tenantId, $connectionId);

        return $connection === null ? null : array_map(DomainSummary::of(...), $this->domains->forConnection($connection));
    }

    /**
     * Why a claim is refused before anything is written, or `null`: no such
     * connection, a domain refused, or a caller who is not fresh enough.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode  $violation
     * @return ?\SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     */
    private function claimRefusal(string $tenantId, string $connectionId, ?ViolationCode $violation): ?DomainResult
    {
        return match (true) {
            $this->connections->find($tenantId, $connectionId) === null           => DomainResult::refused(FailureReason::CONNECTION_NOT_FOUND),
            $violation !== null                                                   => DomainResult::invalid([new SettingViolation(self::DOMAIN, $violation)]),
            !$this->freshness->check(FreshnessOperation::DOMAIN_CLAIM)->isFresh() => DomainResult::refused(FailureReason::FRESHNESS_REQUIRED),
            default                                                               => null,
        };
    }

    /**
     * What is wrong with claiming the domain given, normalised to the name:
     * nothing given, not a host name that could be registered, too long for its
     * record name, or refused.
     *
     * @param  string  $given
     * @param  ?string  $name
     * @param  string  $recordName
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     *
     * @throws \InvalidArgumentException
     */
    private function claimViolation(string $given, ?string $name, string $recordName): ?ViolationCode
    {
        $trimmed = trim($given);
        $length  = strlen($recordName . '.' . ($name ?? $trimmed));

        return match (true) {
            $trimmed === ''                                         => ViolationCode::REQUIRED,
            $length > DomainName::MAX_LENGTH                        => ViolationCode::TOO_LONG,
            $name === null                                          => ViolationCode::INVALID_FORMAT,
            DomainName::isListed($name, $this->settings->refused()) => ViolationCode::NOT_ALLOWED,
            default                                                 => null,
        };
    }

    /**
     * Claim the domain for the locked connection, unless it claimed it already
     * and the claim is live, or another connection holds it verified.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  string  $name
     * @param  string  $recordName
     * @param  string  $token
     * @param  int  $expiry
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function writeClaim(Connection $locked, string $name, string $recordName, #[\SensitiveParameter] string $token, int $expiry, ?ActingIdentity $actor): DomainResult
    {
        $claims   = $this->domains->claimsOf($name, true);
        $existing = $claims->of($locked->id);
        $now      = $this->clock->now();

        $refusal = match (true) {
            $existing !== null && !DomainStanding::isPendingExpired($existing, $now) => DomainResult::invalid([new SettingViolation(self::DOMAIN, ViolationCode::DUPLICATE)]),
            $claims->isVerifiedOtherThan($locked->id)                                => DomainResult::refused(FailureReason::DOMAIN_UNAVAILABLE),
            default                                                                  => null,
        };

        if ($refusal !== null) {
            return $refusal;
        }

        $claim = $existing ?? new Domain;

        $claim->forceFill([
            'connection_id'            => $locked->id,
            'domain'                   => $name,
            'verified_domain'          => null,
            'state'                    => DomainState::PENDING,
            'record_name'              => $recordName,
            'verification_token'       => $token,
            'claimed_at'               => $now,
            'pending_expires_at'       => $now->addSeconds($expiry),
            'verified_at'              => null,
            'last_successful_check_at' => null,
            'linking_suspended_at'     => null,
            'lapses_at'                => null,
            'lapsed_at'                => null,
            'recheck_leased_until'     => null,
        ])->save();

        $this->events->claimed($locked, $claim, $actor);

        return DomainResult::claimed(DomainSummary::of($claim));
    }

    /**
     * The tenant's connection's claim of the domain given, or why there is
     * none: no such connection, or no such claim of it.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $domain
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult|\SineMacula\Laravel\Sso\Models\Domain
     *
     * @throws \InvalidArgumentException
     */
    private function claimFor(string $tenantId, string $connectionId, string $domain): Domain|DomainResult
    {
        $connection = $this->connections->find($tenantId, $connectionId);
        $name       = DomainName::normalize($domain);
        $found      = $connection === null || $name === null ? null : $this->domains->find($connection, $name);

        return match (true) {
            $connection === null => DomainResult::refused(FailureReason::CONNECTION_NOT_FOUND),
            $found      === null => DomainResult::refused(FailureReason::DOMAIN_NOT_FOUND),
            default              => $found,
        };
    }

    /**
     * Why the claim cannot be verified before anything is written, or `null`:
     * it expired, the caller is not fresh enough, it is verified already, or
     * its record was not proven.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $found
     * @return ?\SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     */
    private function verificationRefusal(Domain $found): ?DomainResult
    {
        return match (true) {
            DomainStanding::isPendingExpired($found, $this->clock->now())          => DomainResult::refused(FailureReason::DOMAIN_CLAIM_EXPIRED),
            !$this->freshness->check(FreshnessOperation::DOMAIN_VERIFY)->isFresh() => DomainResult::refused(FailureReason::FRESHNESS_REQUIRED),
            $found->state === DomainState::VERIFIED                                => DomainResult::unchanged(DomainSummary::of($found)),
            default                                                                => $this->lookupRefusal($found),
        };
    }

    /**
     * Take one of the connection's domain checks and look the claim's record
     * up; why that did not prove the claim, or `null` when one of its records
     * is exactly the token.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $found
     * @return ?\SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     */
    private function lookupRefusal(Domain $found): ?DomainResult
    {
        $attempt = $this->limiter->attempt(AttemptSubject::domainCheck($found->connection_id));

        if (!$attempt->isAllowed()) {
            return DomainResult::rateLimited($attempt->retryAfter ?? 1);
        }

        $lookup = $this->resolver->txt(DomainStanding::lookupName($found));

        return match (true) {
            $lookup->isLookupFailed()                      => DomainResult::refused(FailureReason::DOMAIN_LOOKUP_FAILED),
            !$lookup->contains($found->verification_token) => DomainResult::refused(FailureReason::DOMAIN_RECORD_NOT_FOUND),
            default                                        => null,
        };
    }

    /**
     * Verify the locked connection's claim of the domain, which the record
     * proved with the token given, once every claim of the domain is locked:
     * unless the claim went, was claimed again with another token, expired, was
     * verified meanwhile, or another connection holds the domain verified.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  string  $name
     * @param  string  $token
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function writeVerification(Connection $locked, string $name, #[\SensitiveParameter] string $token, ?ActingIdentity $actor): DomainResult
    {
        $claims = $this->domains->claimsOf($name, true);
        $claim  = $claims->of($locked->id);
        $now    = $this->clock->now();

        $refusal = match (true) {
            $claim === null                                           => DomainResult::refused(FailureReason::DOMAIN_NOT_FOUND),
            !ConstantTime::equals($claim->verification_token, $token) => DomainResult::refused(FailureReason::DOMAIN_RECORD_NOT_FOUND),
            DomainStanding::isPendingExpired($claim, $now)            => DomainResult::refused(FailureReason::DOMAIN_CLAIM_EXPIRED),
            $claim->state === DomainState::VERIFIED                   => DomainResult::unchanged(DomainSummary::of($claim)),
            $claims->isVerifiedOtherThan($locked->id)                 => DomainResult::refused(FailureReason::DOMAIN_UNAVAILABLE),
            default                                                   => null,
        };

        return $refusal ?? $this->markVerified($locked, $claim, $now, $actor);
    }

    /**
     * Mark the claim verified for its connection from now, unless the unique
     * index finds the domain verified for another.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function markVerified(Connection $locked, Domain $claim, CarbonImmutable $now, ?ActingIdentity $actor): DomainResult
    {
        $claim->forceFill([
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => $claim->domain,
            'pending_expires_at'       => null,
            'verified_at'              => $now,
            'last_successful_check_at' => $now,
            'linking_suspended_at'     => null,
            'lapses_at'                => null,
            'lapsed_at'                => null,
        ]);

        if (!self::saved($claim)) {
            return DomainResult::refused(FailureReason::DOMAIN_UNAVAILABLE);
        }

        $this->events->verified($locked, $claim, $actor);

        return DomainResult::verified(DomainSummary::of($claim));
    }

    /**
     * Delete the locked connection's claim of the domain, after withdrawing
     * what depends on linking by it, and report it removed, answering it as it
     * was before.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  string  $name
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     */
    private function deleteClaim(Connection $locked, string $name, ?ActingIdentity $actor): DomainResult
    {
        $claim = $this->domains->find($locked, $name, true);

        if ($claim === null) {
            return DomainResult::refused(FailureReason::DOMAIN_NOT_FOUND);
        }

        $summary = DomainSummary::of($claim);

        $this->withdrawal->linkingWithdrawn($locked, $claim);

        $claim->delete();

        $this->events->removed($locked, $claim, $actor);

        return DomainResult::removed($summary);
    }

    /**
     * Run the change in one transaction on the storage connection, against the
     * connection read again locked for update; retried when a deadlock rolled
     * back the outermost transaction.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\Connection): \SineMacula\Laravel\Sso\Domains\DomainResult  $change
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function change(string $tenantId, string $connectionId, \Closure $change): DomainResult
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($tenantId, $connectionId, $change): DomainResult {

            $locked = $this->connections->findForUpdate($tenantId, $connectionId);

            return $locked === null ? DomainResult::refused(FailureReason::CONNECTION_NOT_FOUND) : $change($locked);
        }, self::ATTEMPTS);
    }

    /**
     * Save the claim in a transaction of its own (a savepoint inside the
     * helper's), unless the unique index on `verified_domain` refuses it.
     * Returns whether it was saved; any other error propagates.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private static function saved(Domain $claim): bool
    {
        try {
            DB::connection(StorageConnection::name())->transaction(static fn (): bool => $claim->save());
        } catch (UniqueConstraintViolationException) {
            return false;
        }

        return true;
    }
}
