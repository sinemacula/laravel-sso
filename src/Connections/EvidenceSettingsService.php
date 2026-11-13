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
 * Manages a connection's evidence policy, which takes effect only once the
 * application binds `Evidence\ConnectionEvidencePolicy`.
 *
 * Not a trust or linking change: no version is raised and nothing is voided.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EvidenceSettingsService
{
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
     * The connection's evidence policy, empty when unset, or `null` when the
     * tenant has no such connection.
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
     * Replace the whole policy; an empty one clears it. Freshness is asked
     * before the lock so nothing slow runs under it.
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

        return DB::connection(StorageConnection::name())->transaction(fn (): ConnectionResult => $this->setLocked($tenantId, $connectionId, $policy, $caller, $client));
    }

    /**
     * The stored policy, or empty for a JSON scalar the package never wrote.
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
     * The sorted names the policy changes, ignoring key order in stored maps.
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

            $names[] = 'evidence.' . $name;
        }

        sort($names, SORT_STRING);

        return $names;
    }

    /**
     * Under the connection's lock, refuse what no longer stands or is invalid.
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

        if (!$this->freshness->check(FreshnessOperation::CONNECTION_TRUST, $caller)->isFresh()) {
            return ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED);
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
