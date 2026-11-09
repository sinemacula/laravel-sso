<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Metadata\SamlRefreshRule;
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
 * A SAML connection that, as the change leaves it, has not opted in to
 * following its metadata URL holds no stale deadline
 * (`Metadata\SamlRefreshRule`), and nothing would refresh it before one passed,
 * so the save starts no clock: the import counts as certificates entered by
 * hand, and any stamp from before is cleared, on the record when that is all
 * the save changed. An explicit `metadata_refresh` of `false` on an anchored
 * connection still stamps, the validated fetch counting as it does with any
 * schedule turned off.
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
    /** @var array<string, null> What a connection that holds no deadline keeps of a fetch. */
    private const array NOTHING_STAMPED = ['metadata_fetched_at' => null, 'metadata_valid_until' => null];

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
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function save(
        string $tenantId,
        string $connectionId,
        #[\SensitiveParameter] array $changes,
        ValidatedFetch $fetch,
        ClientContext $client,
        ?Caller $caller = null,
    ): ConnectionResult {
        return DB::connection(StorageConnection::name())->transaction(function () use ($tenantId, $connectionId, $changes, $fetch, $client, $caller): ConnectionResult {

            $locked = $this->finder->findForUpdate($tenantId, $connectionId);

            if ($locked === null || !$this->protocols->isAvailable($locked->protocol)) {
                return ConnectionResult::refused($locked === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
            }

            if (!$this->freshness->check(FreshnessOperation::CONNECTION_TRUST, $caller)->isFresh()) {
                return ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED);
            }

            $result = $this->connections->changeLocked($locked, $changes, $client, $caller);

            if ($result->isSucceeded()) {
                $this->stamped($locked, $fetch, $result, $caller, $client);
            }

            return $result;
        });
    }

    /**
     * Stamp the fetch on the locked connection, or clear what is stamped where
     * it holds no deadline, and report it when it is all the save changed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\ValidatedFetch  $fetch
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function stamped(Connection $locked, ValidatedFetch $fetch, ConnectionResult $result, ?Caller $caller, ClientContext $client): void
    {
        $holds = SamlRefreshRule::holdsDeadline($locked);

        $locked->forceFill($holds ? ['metadata_fetched_at' => $fetch->validatedAt, 'metadata_valid_until' => $fetch->validUntil] : self::NOTHING_STAMPED);

        $renewed = $holds || $locked->isDirty(array_keys(self::NOTHING_STAMPED));

        $locked->save();

        $this->events->connectionUpdated($locked, $result->isChanged() || !$renewed ? [] : ['metadata_fetched_at'], $caller, $client);
    }
}
