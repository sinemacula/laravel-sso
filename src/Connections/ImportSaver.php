<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Metadata\ValidatedFetch;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * Saves what a fetched import proposes (SSO-2.8, SSO-2.11), so that what it
 * saved counts from the fetch it came from: the stale limit applies to every
 * validated fetched resource, and a proposal is one, whether a refresh has run
 * since or not (`Metadata\MetadataExpiry`).
 *
 * `save()` follows one order, in one transaction on the storage connection:
 * find the connection, locked, on the write connection; refuse an unavailable
 * protocol; ask `sso.connection.trust` freshness, since this renews how long
 * the connection is trusted even when it changes no setting, so `stale` is
 * `freshness_required` before anything is validated; then make the change as
 * `ConnectionService::update()` does, whose every rule and refusal applies.
 * Unless that refused, it stamps the fetch as `metadata_fetched_at` and
 * `metadata_valid_until`, overwriting a later refresh's, since these settings
 * are now what the connection holds. A change that changed nothing still
 * stamps, voids nothing and reports `ConnectionUpdated` naming
 * `metadata_fetched_at`, so saving a new import of the same settings recovers
 * an expired connection on the record. The next refresh's due date is left as
 * it is.
 *
 * Metadata given as XML came from no fetch: it has no `ValidatedFetch`, and is
 * saved through `ConnectionService::update()`, as by hand. So is anything an
 * administrator typed in place of a proposal.
 *
 * Every event is dispatched after the transaction commits (SSO-10.5). A
 * database error propagates (SSO-11.4). It holds the lookup, the registry, the
 * freshness gate, the management helpers and the reporter, none of which keeps
 * anything of one request for the next (SSO-11.2). Resolve it from the
 * container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ImportSaver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $finder
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionService  $connections
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $events
     */
    public function __construct(

        /** The tenant-scoped lookup, on the write connection. */
        private ConnectionFinder $finder,

        /** Whether the connection's protocol is available. */
        private ProtocolManager $protocols,

        /** Asks whether the caller's authentication is fresh enough. */
        private FreshnessGate $freshness,

        /** Validates, asks freshness for, writes and reports the change. */
        private ConnectionService $connections,

        /** Reports a save that changed only when the connection was validated. */
        private AdministrationEvents $events,
    ) {}

    /**
     * Make the change to the tenant's connection and stamp the fetch it came
     * from.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Sso\Metadata\ValidatedFetch  $fetch
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function save(string $tenantId, string $connectionId, #[\SensitiveParameter] array $changes, ValidatedFetch $fetch, ?ActingIdentity $actor = null): ConnectionResult
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($tenantId, $connectionId, $changes, $fetch, $actor): ConnectionResult {

            $locked = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($locked === null || !$this->protocols->isAvailable($locked->protocol)) {
                return ConnectionResult::refused($locked === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
            }

            if (!$this->freshness->check(FreshnessOperation::CONNECTION_TRUST)->isFresh()) {
                return ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED);
            }

            $result = $this->connections->changeLocked($locked, $changes, $actor);

            if ($result->isSucceeded()) {
                $this->stamped($locked, $fetch, $result, $actor);
            }

            return $result;
        });
    }

    /**
     * Stamp the fetch on the locked connection, and report it when it is all
     * the save changed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\ValidatedFetch  $fetch
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function stamped(Connection $locked, ValidatedFetch $fetch, ConnectionResult $result, ?ActingIdentity $actor): void
    {
        $locked->forceFill(['metadata_fetched_at' => $fetch->validatedAt, 'metadata_valid_until' => $fetch->validUntil])->save();

        $this->events->connectionUpdated($locked, $result->isChanged() ? [] : ['metadata_fetched_at'], $actor);
    }
}
