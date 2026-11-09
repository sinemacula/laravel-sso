<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * What one protocol refreshes from its identity provider on the schedule and
 * when an administrator asks (SSO-2.8, SSO-11.12): a SAML connection's
 * metadata (`SamlMetadataSource`), an OIDC connection's discovery document and
 * JWKS (`OidcMetadataSource`). The refresh machinery is shared:
 * `MetadataRefresher` lists the due connections of every source's protocol,
 * queues or runs each refresh, logs what did not apply and counts an
 * administrator's attempts; `RefreshClaims` claims a connection with an
 * ownership token; `RefreshWriter` writes under the connection's lock, compares
 * and sets, backs off and reports. A source supplies what differs:
 *
 * - `refreshes()`: whether the schedule refreshes the connection: the source's
 *   own rule on its switch holds, and what it fetches is a URL the package may
 *   fetch;
 * - `refreshing()`: the same of the connections of a due listing at once, which
 *   a source whose rule reads more than the row answers in one read;
 * - `isRefreshable()`: whether what it fetches is a URL the package may fetch,
 *   whatever the switch and whatever has expired, which is what an
 *   administrator's refresh asks, so it can recover a connection;
 * - `claim()`: the snapshot of the connection's trust the refresh is judged
 *   against, read after the connection and before the claim, and the claim
 *   itself through `RefreshClaims`;
 * - `fetch()`: the fetch and the whole validation, outside any transaction,
 *   with the moment it validated;
 * - `write()`: the locked write through `RefreshWriter`, comparing the locked
 *   snapshot with the claim's, replacing exactly what it fetched, voiding what
 *   is in flight and raising the trust version for anything but an addition.
 *
 * A source keeps nothing of one refresh for the next (SSO-11.2). It is an
 * abstract class rather than a contract: the package's own protocols are the
 * only sources, and nothing outside the package implements one.
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
     * Whether the schedule refreshes the connection: the source's own rule on
     * its switch holds and what the refresh fetches is a URL the package may
     * fetch.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    abstract public function refreshes(Connection $connection): bool;

    /**
     * Those of the connections the schedule refreshes, in the order given.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     */
    public function refreshing(array $connections): array
    {
        return array_values(array_filter($connections, $this->refreshes(...)));
    }

    /**
     * Whether the connection can be refreshed at all: it is the source's
     * protocol and what the refresh fetches is a URL the package may fetch,
     * whatever its switch says or what has expired.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    abstract public function isRefreshable(Connection $connection): bool;

    /**
     * Snapshot the connection's trust, as it was read, and claim its refresh;
     * `null` when another server holds the claim or another refresh has written
     * since.
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
