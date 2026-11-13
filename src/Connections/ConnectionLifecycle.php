<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainWithdrawal;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
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
 * Disables and deletes a tenant's connection, revoking its sessions inside the
 * same transaction.
 *
 * Works for an unregistered protocol too, since either leaves less access.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConnectionLifecycle
{
    /** @var list<class-string<\SineMacula\Laravel\Sso\Models\SsoModel>> What is deleted with a connection, in lock order. */
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

        /** Withdraws what depends on a deleted verified domain. */
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
     * Freshness is asked even when the connection is disabled already, which
     * then succeeds as `unchanged`.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function disable(string $tenantId, string $connectionId, ClientContext $client, ?Caller $caller = null): ConnectionResult
    {
        if ($this->finder->find($tenantId, $connectionId) === null) {
            return ConnectionResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        return $this->transaction(function () use ($tenantId, $connectionId, $client, $caller): ConnectionResult {

            $locked = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($locked === null) {
                return ConnectionResult::refused(FailureReason::CONNECTION_NOT_FOUND);
            }

            $refusal = $this->staleRefusal(FreshnessOperation::CONNECTION_DISABLE, $caller) ?? ($locked->enabled ? null : ConnectionResult::unchanged($this->summary($locked)));

            if ($refusal !== null) {
                return $refusal;
            }

            $locked->forceFill(['enabled' => false])->save();

            $this->voider->voidFor($locked);
            $this->revoke($locked, RevocationReason::CONNECTION_DISABLED);
            $this->events->connectionDisabled($locked, $caller, $client);

            return ConnectionResult::disabled($this->summary($locked));
        });
    }

    /**
     * Delete the connection with every row it owns.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function delete(string $tenantId, string $connectionId, ClientContext $client, ?Caller $caller = null): ConnectionResult
    {
        if ($this->finder->find($tenantId, $connectionId) === null) {
            return ConnectionResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        return $this->transaction(function () use ($tenantId, $connectionId, $client, $caller): ConnectionResult {

            $locked = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($locked === null) {
                return ConnectionResult::refused(FailureReason::CONNECTION_NOT_FOUND);
            }

            // The claims are locked before freshness, which may lock the
            // caller's session last
            $claims  = Domain::query()->useWritePdo()->where('connection_id', $locked->id)->orderBy('id')->lockForUpdate()->get()->all();
            $refusal = $this->staleRefusal(FreshnessOperation::CONNECTION_DELETE, $caller);

            if ($refusal !== null) {
                return $refusal;
            }

            $this->withdrawDomains($locked, $claims);
            $this->voider->voidFor($locked);

            foreach (self::OWNED as $model) {
                $model::query()->where('connection_id', $locked->id)->delete();
            }

            $locked->delete();

            $this->revoke($locked, RevocationReason::CONNECTION_DELETED);
            $this->events->connectionDeleted($locked, $caller, $client);

            return ConnectionResult::deleted();
        });
    }

    /**
     * The refusal of a caller whose authentication is stale, `null` when fresh.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     */
    private function staleRefusal(FreshnessOperation $operation, ?Caller $caller): ?ConnectionResult
    {
        return $this->freshness->check($operation, $caller)->isFresh() ? null : ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED);
    }

    /**
     * Withdraw each verified claim of those locked in id order, by a locking
     * read so a claim verified since the snapshot is seen.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<int, \SineMacula\Laravel\Sso\Models\Domain>  $claims
     * @return void
     */
    private function withdrawDomains(Connection $locked, array $claims): void
    {
        foreach ($claims as $claim) {

            if ($claim->state !== DomainState::VERIFIED) {
                continue;
            }

            $this->withdrawal->linkingWithdrawn($locked, $claim);
        }
    }

    /**
     * Revoke the connection's sessions through the contract bound now.
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
