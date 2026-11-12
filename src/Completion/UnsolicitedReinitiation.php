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
 * Answers an unsolicited SAML response by sending the browser to the
 * connection's start URL; the unsolicited identity never carries over.
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

        /** The connection's driver, and whether the connection is usable. */
        private ProtocolManager $protocols,

        /** Reports how the re-initiation ended. */
        private CompletionEvents $events,

        /** Whether the locked connection's refreshed metadata has expired. */
        private MetadataExpiry $metadata,
    ) {}

    /**
     * Validate the response, record its assertion under the connection's lock
     * and answer how it ended.
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
     * The connection of an unsolicited state.
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
     * Lock the connection, refuse what changed since validation, and record the
     * assertion otherwise.
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
     * Why the locked connection no longer takes the response as validated, or
     * `null`.
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
     * Whether the locked connection is still usable at the validated trust
     * version.
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
     * Report how the re-initiation ended and answer it.
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

        $this->events->reinitiated($connection, $outcome->state->client);

        return CompletionResult::reinitiated($reinitiation->startUrl ?? throw new \LogicException('An allowed re-initiation holds its start URL.'));
    }
}
