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
 * Saves what a fetched import proposes and stamps the fetch it came from, so
 * the stale limit counts from that fetch.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ImportSaver
{
    /** @var array<string, null> The stamp of a connection that holds no deadline. */
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

        /** Reports a save that changed only the stamp. */
        private AdministrationEvents $events,
    ) {}

    /**
     * Asks `sso.connection.trust` freshness even for an unchanged import, since
     * the stamp renews how long the connection is trusted.
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
     * Stamp the fetch, or clear the stamp of a SAML connection that does not
     * follow its metadata URL and so holds no deadline.
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
