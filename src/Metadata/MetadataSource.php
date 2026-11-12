<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * What one protocol refreshes from its identity provider; `MetadataRefresher`,
 * `RefreshClaims` and `RefreshWriter` hold what every source shares.
 *
 * Abstract rather than a contract: only the package's own protocols have one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract readonly class MetadataSource
{
    /**
     * The protocol whose connections the source refreshes.
     *
     * @return string
     */
    abstract public function protocol(): string;

    /**
     * Whether the schedule refreshes the connection: its switch is on and what
     * it fetches is a URL the package may fetch.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    abstract public function refreshes(Connection $connection): bool;

    /**
     * Those of the connections the schedule refreshes, in the order given; a
     * source whose rule reads more than the row overrides it to read once.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     */
    public function refreshing(array $connections): array
    {
        return array_values(array_filter($connections, $this->refreshes(...)));
    }

    /**
     * Whether an administrator may refresh the connection: it is the source's
     * protocol and fetches a URL the package may fetch, whatever its switch.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    abstract public function isRefreshable(Connection $connection): bool;

    /**
     * Snapshot the connection's trust and claim its refresh; `null` when
     * another server holds the claim or another refresh has written since.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Metadata\RefreshClaim
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    abstract public function claim(Connection $connection): ?RefreshClaim;

    /**
     * Fetch and validate what the claimed connection refreshes from, outside
     * any transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return \SineMacula\Laravel\Sso\Metadata\FetchedMetadata
     */
    abstract public function fetch(RefreshClaim $claim): FetchedMetadata;

    /**
     * Write what was fetched, or the failure, under the connection's lock,
     * unless the claim was lost or the connection's trust changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \SineMacula\Laravel\Sso\Metadata\FetchedMetadata  $fetched
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    abstract public function write(RefreshClaim $claim, FetchedMetadata $fetched, ?Caller $caller, ClientContext $client): RefreshResult;
}
