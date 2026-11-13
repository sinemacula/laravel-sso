<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Domains;

use Carbon\CarbonImmutable;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Database\RetriedTransaction;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * The tenant-scoped management helpers of a connection's email domains.
 *
 * The DNS lookup runs outside any transaction; the write then re-reads under
 * the connection's lock.
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

    /** @var int Attempts in all at a transaction a deadlock rolled back. */
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
     * Claim exactly the domain, not its subdomains, pending with a new token.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function claim(string $tenantId, string $connectionId, string $domain, ClientContext $client, ?Caller $caller = null): DomainResult
    {
        $name       = DomainName::normalize($domain);
        $recordName = $this->settings->recordName();
        $refusal    = $this->claimRefusal($tenantId, $connectionId, $this->claimViolation($domain, $name, $recordName));

        if ($refusal !== null || $name === null) {
            return $refusal ?? DomainResult::invalid([new SettingViolation(self::DOMAIN, ViolationCode::INVALID_FORMAT)]);
        }

        $token  = bin2hex(random_bytes(self::TOKEN_BYTES));
        $expiry = $this->settings->pendingExpirySeconds();

        return $this->change($tenantId, $connectionId, fn (Connection $locked): DomainResult => $this->writeClaim($locked, $name, $recordName, $token, $expiry, $caller, $client));
    }

    /**
     * Verify the tenant's connection's claim of the domain by its TXT record.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function verify(string $tenantId, string $connectionId, string $domain, ClientContext $client, ?Caller $caller = null): DomainResult
    {
        $found = $this->claimFor($tenantId, $connectionId, $domain);

        if ($found instanceof DomainResult) {
            return $found;
        }

        $token = $found->verification_token;

        return $this->verificationRefusal($found, $caller)
            ?? $this->change($tenantId, $connectionId, fn (Connection $locked): DomainResult => $this->writeVerification($locked, $found, $token, $caller, $client));
    }

    /**
     * Remove the tenant's connection's claim of the domain, whatever its state.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function remove(string $tenantId, string $connectionId, string $domain, ClientContext $client, ?Caller $caller = null): DomainResult
    {
        $found = $this->claimFor($tenantId, $connectionId, $domain);

        if ($found instanceof DomainResult) {
            return $found;
        }

        return $this->change($tenantId, $connectionId, fn (Connection $locked): DomainResult => $this->deleteClaim($locked, $found->domain, $caller, $client));
    }

    /**
     * The tenant's connection's claim of the domain, or `null`.
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
     * Every claim of the tenant's connection, oldest first; `null` without the
     * connection.
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
     * Why a claim is refused before anything is written, or `null`.
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
            $this->connections->find($tenantId, $connectionId) === null => DomainResult::refused(FailureReason::CONNECTION_NOT_FOUND),
            $violation !== null                                         => DomainResult::invalid([new SettingViolation(self::DOMAIN, $violation)]),
            default                                                     => null,
        };
    }

    /**
     * What is wrong with claiming the domain given, or `null`.
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
     * Claim the domain unless the connection's own claim is live or another
     * connection holds it verified.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  string  $name
     * @param  string  $recordName
     * @param  string  $token
     * @param  int  $expiry
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function writeClaim(
        Connection $locked,
        string $name,
        string $recordName,
        #[\SensitiveParameter] string $token,
        int $expiry,
        ?Caller $caller,
        ClientContext $client,
    ): DomainResult {
        $claims   = $this->domains->claimsOf($name, true);
        $existing = $claims->of($locked->id);
        $now      = $this->clock->now();

        $refusal = match (true) {
            $existing !== null && !DomainStanding::isPendingExpired($existing, $now) => DomainResult::invalid([new SettingViolation(self::DOMAIN, ViolationCode::DUPLICATE)]),
            $claims->isVerifiedOtherThan($locked->id)                                => DomainResult::refused(FailureReason::DOMAIN_UNAVAILABLE),
            !$this->isFresh(FreshnessOperation::DOMAIN_CLAIM, $caller)               => DomainResult::refused(FailureReason::FRESHNESS_REQUIRED),
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

        $this->events->claimed($locked, $claim, $caller, $client);

        return DomainResult::claimed(DomainSummary::of($claim));
    }

    /**
     * The tenant's connection's claim of the domain, or why there is none.
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
     * Why the claim cannot be verified before anything is written, or `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $found
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     */
    private function verificationRefusal(Domain $found, ?Caller $caller): ?DomainResult
    {
        return match (true) {
            DomainStanding::isPendingExpired($found, $this->clock->now()) => DomainResult::refused(FailureReason::DOMAIN_CLAIM_EXPIRED),
            !$this->isFresh(FreshnessOperation::DOMAIN_VERIFY, $caller)   => DomainResult::refused(FailureReason::FRESHNESS_REQUIRED),
            $found->state === DomainState::VERIFIED                       => DomainResult::unchanged(DomainSummary::of($found)),
            default                                                       => $this->lookupRefusal($found),
        };
    }

    /**
     * Take a domain check and look the record up; why it did not prove the
     * claim, or `null`.
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
     * Verify the claim with every claim of the domain locked, unless it changed
     * since the lookup or another connection holds the domain verified.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $seen
     * @param  string  $token
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function writeVerification(Connection $locked, Domain $seen, #[\SensitiveParameter] string $token, ?Caller $caller, ClientContext $client): DomainResult
    {
        $claims = $this->domains->claimsOf($seen->domain, true);
        $claim  = $claims->of($locked->id);
        $now    = $this->clock->now();

        $refusal = match (true) {
            $claim === null                                             => DomainResult::refused(FailureReason::DOMAIN_NOT_FOUND),
            !ConstantTime::equals($claim->verification_token, $token)   => DomainResult::refused(FailureReason::DOMAIN_RECORD_NOT_FOUND),
            DomainStanding::isPendingExpired($claim, $now)              => DomainResult::refused(FailureReason::DOMAIN_CLAIM_EXPIRED),
            $claim->state === DomainState::VERIFIED                     => DomainResult::unchanged(DomainSummary::of($claim)),
            self::lapsedSince($claim, $seen)                            => DomainResult::refused(FailureReason::DOMAIN_RECORD_NOT_FOUND),
            $claims->isVerifiedOtherThan($locked->id)                   => DomainResult::refused(FailureReason::DOMAIN_UNAVAILABLE),
            !$this->isFresh(FreshnessOperation::DOMAIN_VERIFY, $caller) => DomainResult::refused(FailureReason::FRESHNESS_REQUIRED),
            default                                                     => null,
        };

        return $refusal ?? $this->markVerified($locked, $claim, $now, $caller, $client);
    }

    /**
     * Mark the claim verified from now, unless the unique index finds the
     * domain verified for another connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    private function markVerified(Connection $locked, Domain $claim, CarbonImmutable $now, ?Caller $caller, ClientContext $client): DomainResult
    {
        $claim->forceFill([
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => $claim->domain,
            'pending_expires_at'       => null,
            'verified_at'              => $now,
            'verification_generation'  => $claim->verification_generation + 1,
            'last_successful_check_at' => $now,
            'linking_suspended_at'     => null,
            'lapses_at'                => null,
            'lapsed_at'                => null,
        ]);

        if (!self::saved($claim)) {
            return DomainResult::refused(FailureReason::DOMAIN_UNAVAILABLE);
        }

        $this->events->verified($locked, $claim, $caller, $client);

        return DomainResult::verified(DomainSummary::of($claim));
    }

    /**
     * Withdraw what depends on the claim, delete it, and answer it as it was.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  string  $name
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     */
    private function deleteClaim(Connection $locked, string $name, ?Caller $caller, ClientContext $client): DomainResult
    {
        $claim = $this->domains->find($locked, $name, true);

        if ($claim === null) {
            return DomainResult::refused(FailureReason::DOMAIN_NOT_FOUND);
        }

        if (!$this->isFresh(FreshnessOperation::DOMAIN_REMOVE, $caller)) {
            return DomainResult::refused(FailureReason::FRESHNESS_REQUIRED);
        }

        $summary = DomainSummary::of($claim);

        $this->withdrawal->linkingWithdrawn($locked, $claim);

        $claim->delete();

        $this->events->removed($locked, $claim, $caller, $client);

        return DomainResult::removed($summary);
    }

    /**
     * Run the change in one storage transaction against the connection locked
     * for update, retried on deadlock when outermost.
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
        return RetriedTransaction::run(DB::connection(StorageConnection::name()), function () use ($tenantId, $connectionId, $change): DomainResult {

            $locked = $this->connections->findForUpdate($tenantId, $connectionId);

            return $locked === null ? DomainResult::refused(FailureReason::CONNECTION_NOT_FOUND) : $change($locked);
        }, self::ATTEMPTS);
    }

    /**
     * Whether the caller authenticated recently enough for the operation.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isFresh(FreshnessOperation $operation, ?Caller $caller): bool
    {
        return $this->freshness->check($operation, $caller)->isFresh();
    }

    /**
     * Whether the claim lapsed after it was read for the lookup, so the older
     * answer must not overrule it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $seen
     * @return bool
     */
    private static function lapsedSince(Domain $claim, Domain $seen): bool
    {
        return $claim->state === DomainState::LAPSED
            && ($seen->state !== DomainState::LAPSED || $claim->lapsed_at?->getTimestamp() !== $seen->lapsed_at?->getTimestamp());
    }

    /**
     * Save the claim in a savepoint; `false` when the unique index on
     * `verified_domain` refuses it.
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
