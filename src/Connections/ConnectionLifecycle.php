<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainWithdrawal;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * The management helpers that disable and delete a tenant's connection
 * (SSO-2.1, SSO-2.11, SSO-4.5), for the application's own administration
 * screens: who may call them is the application's authorisation, never the
 * package's.
 *
 * Each is scoped to a tenant, as `ConnectionService` is (another tenant's
 * connection is `connection_not_found`, exactly as an unknown one), and goes in
 * one order:
 *
 * 1. The connection is found by a plain read on the write connection; none is
 *    `connection_not_found`.
 * 2. The freshness contract is asked: `sso.connection.disable` to disable,
 *    even a connection already disabled, and `sso.connection.delete` to
 *    delete; `stale` is `freshness_required`.
 * 3. In one transaction on the storage connection (a savepoint inside the
 *    caller's), the connection's row is read again, locked, which every
 *    completion and redemption through it waits for; gone meanwhile, it is
 *    `connection_not_found`.
 * 4. Disabling reads `enabled` from the locked row: a disabled connection is
 *    `unchanged`, with nothing written or reported. Otherwise it sets `enabled`
 *    off, voids what is in flight through the connection (`InFlightVoider`),
 *    revokes the sessions established through it, and reports
 *    `ConnectionDisabled`; its domains and links are kept.
 * 5. Deleting locks the connection's domain claims, in id order, and for each
 *    verified one calls `Domains\DomainWithdrawal::linkingWithdrawn()` with the
 *    locked rows; voids what is in flight; deletes the connection's domains,
 *    authorisation requests, handoff codes, links and keys, then the
 *    connection; revokes the sessions established through it; and reports one
 *    `ConnectionDeleted`, with no event per link.
 *
 * The revocation is `Contracts\SessionRevocation`, resolved from the container
 * at that moment, with `RevocationScope::connection()` and the reason
 * `connection_disabled` or `connection_deleted`. It runs inside the
 * transaction, so an adapter that writes through the same Laravel connection
 * commits or rolls back with the change (decision D5); an exception it throws
 * rolls the change back, with nothing reported, and propagates. Events are
 * dispatched once the change commits, never when it rolls back (SSO-10.5).
 *
 * A connection whose protocol is no longer registered can still be disabled and
 * deleted: either leaves less access than before. A refusal at any step writes,
 * revokes and reports nothing. An empty or overlong tenant id is an
 * `InvalidArgumentException`; a database error propagates (SSO-11.4).
 *
 * It holds the lookup, the freshness gate, the voider, the domain withdrawal,
 * the reporter, the registry, the secrets and the container, none of which
 * keeps anything of one request for the next (SSO-11.2). Resolve it from the
 * container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConnectionLifecycle
{
    /** @var list<class-string<\SineMacula\Laravel\Sso\Models\SsoModel>> What is deleted with a connection, in the order the rows are locked. */
    private const array OWNED = [
        Domain::class,
        AuthorizationRequest::class,
        HandoffCode::class,
        Link::class,
        ConnectionKey::class,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $finder
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Connections\InFlightVoider  $voider
     * @param  \SineMacula\Laravel\Sso\Domains\DomainWithdrawal  $withdrawal
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $events
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSecrets  $secrets
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The tenant-scoped lookup, on the write connection. */
        private ConnectionFinder $finder,

        /** The freshness contract every change asks first. */
        private FreshnessGate $freshness,

        /** Voids what the connection has in flight. */
        private InFlightVoider $voider,

        /** Withdraws what depends on linking by a verified domain deleted. */
        private DomainWithdrawal $withdrawal,

        /** The reporter of every change. */
        private AdministrationEvents $events,

        /** The protocol drivers, for the summary. */
        private ProtocolManager $protocols,

        /** The connections' encrypted secrets, masked in the summary. */
        private ConnectionSecrets $secrets,

        /** Resolves the revocation contract at each change. */
        private Container $container,
    ) {}

    /**
     * Disable the tenant's connection: void what is in flight through it and
     * revoke the sessions established through it. Freshness is asked even when
     * it is disabled already, which then succeeds as `unchanged`.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function disable(string $tenantId, string $connectionId, ?ActingIdentity $actor = null): ConnectionResult
    {
        $refusal = $this->refusal($tenantId, $connectionId, FreshnessOperation::CONNECTION_DISABLE);

        return $refusal ?? $this->transaction(function () use ($tenantId, $connectionId, $actor): ConnectionResult {

            $locked = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($locked === null || !$locked->enabled) {
                return $locked === null ? ConnectionResult::refused(FailureReason::CONNECTION_NOT_FOUND) : ConnectionResult::unchanged($this->summary($locked));
            }

            $locked->forceFill(['enabled' => false])->save();

            $this->voider->voidFor($locked);
            $this->revoke($locked, RevocationReason::CONNECTION_DISABLED);
            $this->events->connectionDisabled($locked, $actor);

            return ConnectionResult::disabled($this->summary($locked));
        });
    }

    /**
     * Delete the tenant's connection, with its domains, links, keys,
     * authorisation requests and handoff codes, and revoke the sessions
     * established through it.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function delete(string $tenantId, string $connectionId, ?ActingIdentity $actor = null): ConnectionResult
    {
        $refusal = $this->refusal($tenantId, $connectionId, FreshnessOperation::CONNECTION_DELETE);

        return $refusal ?? $this->transaction(function () use ($tenantId, $connectionId, $actor): ConnectionResult {

            $locked = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($locked === null) {
                return ConnectionResult::refused(FailureReason::CONNECTION_NOT_FOUND);
            }

            $this->withdrawDomains($locked);
            $this->voider->voidFor($locked);

            foreach (self::OWNED as $model) {
                $model::query()->where('connection_id', $locked->id)->delete();
            }

            $locked->delete();

            $this->revoke($locked, RevocationReason::CONNECTION_DELETED);
            $this->events->connectionDeleted($locked, $actor);

            return ConnectionResult::deleted();
        });
    }

    /**
     * Why the change cannot start, or `null` when it can: the tenant has no
     * such connection, or the caller is not fresh enough for the operation.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @return ?\SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function refusal(string $tenantId, string $connectionId, FreshnessOperation $operation): ?ConnectionResult
    {
        return match (true) {
            $this->finder->find($tenantId, $connectionId) === null => ConnectionResult::refused(FailureReason::CONNECTION_NOT_FOUND),
            !$this->freshness->check($operation)->isFresh()        => ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED),
            default                                                => null,
        };
    }

    /**
     * Lock the locked connection's domain claims, in id order, and withdraw
     * what depends on linking by each verified one.
     *
     * Every lookup of the claims is a locking read, so a claim verified since
     * the caller's transaction began is seen, whatever its snapshot.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return void
     */
    private function withdrawDomains(Connection $locked): void
    {
        $claims = Domain::query()->useWritePdo()->where('connection_id', $locked->id)->orderBy('id')->lockForUpdate()->get()->all();

        foreach ($claims as $claim) {

            if ($claim->state !== DomainState::VERIFIED) {
                continue;
            }

            $this->withdrawal->linkingWithdrawn($locked, $claim);
        }
    }

    /**
     * Revoke the sessions established through the locked connection, for the
     * reason, through the revocation contract bound now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason  $reason
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function revoke(Connection $locked, RevocationReason $reason): void
    {
        $this->container->make(SessionRevocation::class)->revoke(RevocationScope::connection($locked->tenant_id, $locked->id, $reason));
    }

    /**
     * The connection's summary.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function summary(Connection $connection): ConnectionSummary
    {
        return ConnectionSummary::of($connection, $this->protocols, $this->secrets);
    }

    /**
     * Run the callback in one transaction on the storage connection.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Connections\ConnectionResult  $callback
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function transaction(\Closure $callback): ConnectionResult
    {
        return DB::connection(StorageConnection::name())->transaction($callback);
    }
}
