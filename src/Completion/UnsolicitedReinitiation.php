<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\ReinitiatingDriver;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Reinitiation;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;

/**
 * Answers an unsolicited SAML response by re-initiation (SSO-5.8, SSO-6.11),
 * once the correlation step handed it over: the response is validated by the
 * unsolicited profile, the connection is checked again under its lock, the
 * assertion is recorded against replay, and the browser is sent to the
 * connection's start URL so the application starts an SP-initiated flow. It
 * never consumes or creates an authorisation request, never resolves a link,
 * never issues a handoff code and never verifies a result: the unsolicited
 * identity never carries into the new flow.
 *
 * 1. Outside any transaction, the connection's trust version is captured from
 *    the row the completion read, and the driver
 *    (`Contracts\ReinitiatingDriver`) validates the response against what the
 *    connection holds; validation may be slow, so no lock is held across it. A
 *    refusal ends here.
 * 2. In one transaction on the storage connection, the connection's row alone
 *    is locked for update on the write connection (the package's lock order,
 *    `flows.md`, with no request or code row involved), and checked again,
 *    recording nothing when it is refused. A connection gone, no longer usable
 *    (`Protocols\ProtocolManager::isUsable()`) or whose trust version moved
 *    since step 1 (a certificate distrusted, a metadata anchor changed, the
 *    connection disabled and enabled again) is `connection_unavailable`; one
 *    whose refreshed metadata has expired by now (`Metadata\MetadataExpiry`) is
 *    `metadata_expired`; one that no longer allows IdP-initiated sign-in (the
 *    driver's `startUrl()` of the locked row is `null`) is
 *    `unsolicited_not_allowed`; and one whose start URL changed since step 1 is
 *    `connection_unavailable`. Otherwise the assertion's replay record is
 *    recorded by the stage registered for `replay_recording`, exactly as a
 *    solicited response's is: `assertion_expired` once its expiry is not after
 *    now, `replayed` when it was recorded before.
 * 3. After that transaction commits, a re-initiation reports
 *    `UnsolicitedResponseReinitiated` and answers
 *    `CompletionResult::reinitiated()` with the start URL; a refusal reports
 *    one `FlowFailed` for the flow and answers `CompletionResult::rejected()`,
 *    since an unsolicited response has no trusted redirect target. Each event
 *    names the connection, its tenant and its protocol only (SSO-10.4).
 *
 * A database error propagates as a server error (SSO-11.4) and rolls the record
 * back. It holds the drivers' registry, the reporter and the metadata expiry,
 * none of which keeps anything of one completion for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UnsolicitedReinitiation
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionEvents  $events
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataExpiry  $metadata
     */
    public function __construct(

        /** The connection's driver, and whether the connection is still usable under its lock. */
        private ProtocolManager $protocols,

        /** Reports how the re-initiation ended. */
        private CompletionEvents $events,

        /** Whether the locked connection's refreshed metadata has expired. */
        private MetadataExpiry $metadata,
    ) {}

    /**
     * Re-initiate the unsolicited response the state holds, recording its
     * assertion through the replay stage given, and answer how it ended.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Contracts\CompletionStage  $replay
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function run(Flow $flow, CompletionState $state, CompletionStage $replay): CompletionResult
    {
        $connection   = self::connectionOf($state);
        $trustVersion = $connection->trust_version;
        $reinitiation = $this->driverOf($connection)->reinitiate($connection, $state->request);
        $record       = $reinitiation->replay;

        if ($record === null) {
            return $this->answer($flow, $connection, StageOutcome::refuse($state, $reinitiation->reason ?? FailureReason::RESPONSE_INVALID), $reinitiation);
        }

        $outcome = DB::connection(StorageConnection::name())->transaction(fn (): StageOutcome => $this->locked($state, $trustVersion, $record, $reinitiation->startUrl, $replay));

        return $this->answer($flow, $connection, $outcome, $reinitiation);
    }

    /**
     * The connection of a state handed over by the correlation step, which
     * holds the connection read and the unsolicited correlation.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private static function connectionOf(CompletionState $state): Connection
    {
        if ($state->correlation?->isUnsolicited() !== true) {
            throw new \LogicException('Only an unsolicited response is re-initiated.');
        }

        return $state->connection ?? throw new \LogicException('A re-initiated response holds its connection.');
    }

    /**
     * The connection's driver, which must re-initiate.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Contracts\ReinitiatingDriver
     *
     * @throws \LogicException
     */
    private function driverOf(Connection $connection): ReinitiatingDriver
    {
        $driver = $this->protocols->protocol($connection->protocol);

        if (!$driver instanceof ReinitiatingDriver) {
            throw new \LogicException(sprintf('The [%s] driver does not re-initiate an unsolicited response.', $connection->protocol));
        }

        return $driver;
    }

    /**
     * In the transaction: lock the connection's row, refuse it gone, no longer
     * usable, with its trust changed, or no longer taking the response as
     * validated, and record the assertion otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  int  $trustVersion
     * @param  \SineMacula\Laravel\Sso\Protocols\ReplayRecord  $record
     * @param  ?string  $startUrl
     * @param  \SineMacula\Laravel\Sso\Contracts\CompletionStage  $replay
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function locked(CompletionState $state, int $trustVersion, ReplayRecord $record, ?string $startUrl, CompletionStage $replay): StageOutcome
    {
        $locked = Connection::query()->useWritePdo()->lockForUpdate()->whereKey(self::connectionOf($state)->id)->first();

        if (!$this->isUnchanged($locked, $trustVersion)) {
            return StageOutcome::refuse($state, FailureReason::CONNECTION_UNAVAILABLE);
        }

        $reason = $this->refusalOf($locked, $startUrl);

        if ($reason !== null) {
            return StageOutcome::refuse($state, $reason);
        }

        return $replay->run($state->withConnection($locked)->withReplay($record));
    }

    /**
     * Why the locked connection no longer takes the response as validated: its
     * refreshed metadata expired by now, IdP-initiated sign-in no longer
     * allowed, or its start URL no longer the one validated with; `null` when
     * it still does.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  ?string  $startUrl
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function refusalOf(Connection $locked, ?string $startUrl): ?FailureReason
    {
        $current = $this->driverOf($locked)->startUrl($locked);

        return match (true) {
            $this->metadata->isExpired($locked) => FailureReason::METADATA_EXPIRED,
            $current === null                   => FailureReason::UNSOLICITED_NOT_ALLOWED,
            $current !== $startUrl              => FailureReason::CONNECTION_UNAVAILABLE,
            default                             => null,
        };
    }

    /**
     * Whether the locked connection is still there, at the trust version the
     * validation was based on, and usable.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  int  $trustVersion
     * @return bool
     *
     * @phpstan-assert-if-true !null $locked
     */
    private function isUnchanged(?Connection $locked, int $trustVersion): bool
    {
        if ($locked === null || $locked->trust_version !== $trustVersion) {
            return false;
        }

        return $this->protocols->isUsable($locked);
    }

    /**
     * Report how the re-initiation ended, and answer it: `reinitiated` with the
     * start URL once the assertion is recorded, `rejected` for the reason
     * otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @param  \SineMacula\Laravel\Sso\Protocols\Reinitiation  $reinitiation
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \LogicException
     */
    private function answer(Flow $flow, Connection $connection, StageOutcome $outcome, Reinitiation $reinitiation): CompletionResult
    {
        $reason = $outcome->reason;

        if ($reason !== null) {

            $this->events->report($flow, $outcome);

            return CompletionResult::rejected($reason);
        }

        $this->events->reinitiated($connection);

        return CompletionResult::reinitiated($reinitiation->startUrl ?? throw new \LogicException('An allowed re-initiation holds its start URL.'));
    }
}
