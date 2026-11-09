<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\AdministrationEvents;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Evidence\EvidenceRules;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Linking\LinkingSettings;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * The management helper for a connection's evidence policy (SSO-8.7, SSO-2.12),
 * for the application's own administration screens: who may call it is the
 * application's authorisation, never the package's. A policy takes effect only
 * once the application binds `Evidence\ConnectionEvidencePolicy`.
 *
 * `set()` replaces the whole policy (`Evidence\EvidenceRules` says what it may
 * hold, and an empty one clears it, so nothing is accepted). It goes in one
 * order, as `ConnectionLifecycle` does, so nothing slow runs under a lock:
 *
 * 1. the connection is found by a plain read on the write connection; none is
 *    `connection_not_found`;
 * 2. the freshness contract is asked with `sso.connection.trust`; `stale` is
 *    `freshness_required`;
 * 3. in one transaction on the storage connection, the connection's row is read
 *    again locked, the only lock taken; gone is `connection_not_found`, and a
 *    protocol no longer available `protocol_unavailable`;
 * 4. the policy is judged for that protocol, and its `max_age_seconds` against
 *    the ceiling `sso.linking.evidence_max_age_seconds`, with every violation
 *    answered as `settings_invalid`;
 * 5. a policy the row already holds, whatever the key order of its maps, is
 *    `unchanged`, and writes and reports nothing;
 * 6. the policy is written, and `ConnectionUpdated` is reported after commit,
 *    naming what changed as `evidence.*`, in sorted order, never a value.
 *
 * This is no protocol trust change and no linking change: `trust_version` and
 * `linking_version` stay, and no request, code or reservation is touched. A
 * code already issued is judged at its redemption by the policy written. A
 * redemption reads the policy from the same row, locked, so it sees it either
 * side of this transaction and never partly.
 *
 * The values given are never logged, reported or echoed by a violation. An
 * empty or overlong tenant id is an `InvalidArgumentException`; a database
 * error propagates (SSO-11.4). It holds the lookup, the freshness gate, the
 * reporter, the registry, the secrets and the settings, none of which keeps
 * anything of one request for the next (SSO-11.2). Resolve it from the
 * container per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EvidenceSettingsService
{
    /** @var string What `ConnectionUpdated` names each change under. */
    private const string CHANGED_PREFIX = 'evidence.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $finder
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Administration\AdministrationEvents  $events
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSecrets  $secrets
     * @param  \SineMacula\Laravel\Sso\Linking\LinkingSettings  $settings
     */
    public function __construct(

        /** The tenant-scoped lookup, on the write connection. */
        private ConnectionFinder $finder,

        /** The freshness contract every change asks first. */
        private FreshnessGate $freshness,

        /** The reporter of every change. */
        private AdministrationEvents $events,

        /** The protocol drivers, for availability and the summary. */
        private ProtocolManager $protocols,

        /** The connections' encrypted secrets, masked in the summary. */
        private ConnectionSecrets $secrets,

        /** The ceiling a policy's maximum age may only tighten. */
        private LinkingSettings $settings,
    ) {}

    /**
     * The tenant's connection's evidence policy, or `null` when it has no such
     * connection. A connection with none holds an empty one.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return ?array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public function get(string $tenantId, string $connectionId): ?array
    {
        $connection = $this->finder->find($tenantId, $connectionId);

        return $connection === null ? null : self::stored($connection);
    }

    /**
     * Replace the tenant's connection's evidence policy.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  array<array-key, mixed>  $policy
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function set(string $tenantId, string $connectionId, #[\SensitiveParameter] array $policy, ClientContext $client, ?Caller $caller = null): ConnectionResult
    {
        if ($this->finder->find($tenantId, $connectionId) === null) {
            return ConnectionResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        if (!$this->freshness->check(FreshnessOperation::CONNECTION_TRUST, $caller)->isFresh()) {
            return ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED);
        }

        return DB::connection(StorageConnection::name())->transaction(fn (): ConnectionResult => $this->setLocked($tenantId, $connectionId, $policy, $caller, $client));
    }

    /**
     * What the row holds, or an empty policy for what is no policy at all: a
     * JSON scalar the package never wrote, which a `set()` can still replace.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array<array-key, mixed>
     */
    private static function stored(Connection $connection): array
    {
        $stored = $connection->evidence_policy;

        return is_array($stored) ? $stored : [];
    }

    /**
     * The names, sorted, of what the policy changes in what is stored, under
     * every name either holds, so a stored name no policy has can be cleared. A
     * stored map may come back with its keys in any order.
     *
     * @param  array<array-key, mixed>  $stored
     * @param  array<array-key, mixed>  $policy
     * @return list<string>
     */
    private static function changedNames(array $stored, #[\SensitiveParameter] array $policy): array
    {
        $names = [];

        foreach (array_keys([...$stored, ...$policy]) as $name) {

            if (SettingRules::isSame($stored[$name] ?? null, $policy[$name] ?? null)) {
                continue;
            }

            $names[] = self::CHANGED_PREFIX . $name;
        }

        sort($names, SORT_STRING);

        return $names;
    }

    /**
     * Under the connection's lock: refuse what no longer stands or is invalid,
     * and write what changes.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  array<array-key, mixed>  $policy
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function setLocked(string $tenantId, string $connectionId, #[\SensitiveParameter] array $policy, ?Caller $caller, ClientContext $client): ConnectionResult
    {
        $locked = $this->finder->findForUpdate($tenantId, $connectionId);

        if ($locked === null || !$this->protocols->isAvailable($locked->protocol)) {
            return ConnectionResult::refused($locked === null ? FailureReason::CONNECTION_NOT_FOUND : FailureReason::PROTOCOL_UNAVAILABLE);
        }

        $violations = EvidenceRules::violations($policy, $locked->protocol, $this->settings->evidenceMaxAgeSeconds());

        return $violations === [] ? $this->written($locked, $policy, $caller, $client) : ConnectionResult::invalid($violations);
    }

    /**
     * Write what the policy changes and report it, or answer `unchanged`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<array-key, mixed>  $policy
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function written(Connection $locked, #[\SensitiveParameter] array $policy, ?Caller $caller, ClientContext $client): ConnectionResult
    {
        $names = self::changedNames(self::stored($locked), $policy);

        if ($names === []) {
            return ConnectionResult::unchanged($this->summary($locked));
        }

        $locked->forceFill(['evidence_policy' => $policy === [] ? null : $policy])->save();

        $this->events->connectionUpdated($locked, $names, $caller, $client);

        return ConnectionResult::updated($this->summary($locked), $names);
    }

    /**
     * The summary of the connection.
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
}
