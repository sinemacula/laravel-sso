<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Seams\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * What every `Contracts\Freshness` must guarantee, as tests: use it in a test
 * case of the binding and implement the methods it declares.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait FreshnessContract
{
    /**
     * No caller, a session of another identity, and, for a binding that judges
     * sessions, a caller with no session are each `stale`.
     *
     * @return void
     */
    public function testFreshnessFindsAnUnjudgeableCallerStale(): void
    {
        $freshness = $this->freshness();
        $operation = $this->freshnessOperation();
        $caller    = $this->callerAuthenticatedSecondsAgo(10);

        Assert::assertSame(FreshnessOutcome::STALE, $freshness->check($operation, 3600, null), 'No caller must be stale.');
        Assert::assertSame(FreshnessOutcome::STALE, $freshness->check($operation, 3600, $this->otherIdentitysSession()), 'Another identity\'s session must be stale.');

        if (!$this->judgesSessions()) {
            return;
        }

        Assert::assertSame(FreshnessOutcome::STALE, $freshness->check($operation, 3600, new Caller($caller->identity)), 'A caller with no session must be stale.');
    }

    /**
     * A caller is `fresh` within the maximum age asked, whatever it is, and
     * `stale` beyond it.
     *
     * @return void
     */
    public function testFreshnessIsFreshOnlyWithinTheMaximumAge(): void
    {
        $freshness = $this->freshness();
        $operation = $this->freshnessOperation();
        $caller    = $this->callerAuthenticatedSecondsAgo(600);

        Assert::assertSame(FreshnessOutcome::FRESH, $freshness->check($operation, 660, $caller), 'A caller within the maximum age must be fresh.');
        Assert::assertSame(FreshnessOutcome::FRESH, $freshness->check($operation, 1200, $caller), 'A longer maximum age must not make the caller stale.');
        Assert::assertSame(FreshnessOutcome::STALE, $freshness->check($operation, 540, $caller), 'A caller beyond the maximum age must be stale.');
    }

    /**
     * Asked again inside a transaction on the storage connection, each caller
     * gets the answer it got outside one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFreshnessAnswersTheSameInsideATransaction(): void
    {
        $freshness = $this->freshness();
        $operation = $this->freshnessOperation();
        $callers   = [$this->callerAuthenticatedSecondsAgo(10), $this->callerAuthenticatedSecondsAgo(600)];
        $asked     = static fn (): array => array_map(static fn (Caller $caller): FreshnessOutcome => $freshness->check($operation, 300, $caller), $callers);

        $outside = $asked();

        Assert::assertSame([FreshnessOutcome::FRESH, FreshnessOutcome::STALE], $outside, 'The recent caller must be fresh and the other stale.');
        Assert::assertSame($outside, DB::connection(StorageConnection::name())->transaction($asked), 'Inside the transaction each caller must get the same answer.');
    }

    /**
     * Whether the binding judges the caller's session, so a caller with none
     * cannot be judged.
     *
     * @return bool
     */
    protected function judgesSessions(): bool
    {
        return true;
    }

    /**
     * The binding under test.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\Freshness
     */
    abstract protected function freshness(): Freshness;

    /**
     * An operation the binding judges by the caller's authentication alone.
     *
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    abstract protected function freshnessOperation(): FreshnessOperation;

    /**
     * A caller on a session of its own identity that authenticated that many
     * seconds ago.
     *
     * @param  int  $seconds
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    abstract protected function callerAuthenticatedSecondsAgo(int $seconds): Caller;

    /**
     * A caller naming an identity with the id of another identity's session,
     * which authenticated just now.
     *
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    abstract protected function otherIdentitysSession(): Caller;
}
