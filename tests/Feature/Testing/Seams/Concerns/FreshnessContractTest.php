<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing\Seams\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\FreshnessContract;
use Tests\TestCase;

/**
 * Feature tests for the freshness kit, run against a binding that keeps it and
 * ones that do not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(FreshnessContract::class)]
final class FreshnessContractTest extends TestCase
{
    use FreshnessContract {
        judgesSessions as private judgesSessionsByDefault;
    }

    /** @var string A second connection to the same database. */
    private const string STORE = 'kit_store';

    /** @var array<string, array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: \Carbon\CarbonImmutable}> Each session's identity and authentication time. */
    private array $sessions = [];

    /** @var ?string How the binding breaks the contract, if it does. */
    private ?string $flaw = null;

    /** @var ?bool Whether the binding judges sessions, or null for the kit's default. */
    private ?bool $judges = null;

    /**
     * The kit fails a binding that finds no caller fresh.
     *
     * @return void
     */
    public function testCatchesABindingThatFindsNoCallerFresh(): void
    {
        $this->flaw = 'no-caller';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('No caller must be stale.');

        $this->testFreshnessFindsAnUnjudgeableCallerStale();
    }

    /**
     * The kit fails a binding that judges the session without its identity.
     *
     * @return void
     */
    public function testCatchesABindingThatIgnoresTheSessionsIdentity(): void
    {
        $this->flaw = 'identity';

        $this->expectException(AssertionFailedError::class);

        $this->testFreshnessFindsAnUnjudgeableCallerStale();
    }

    /**
     * The kit fails a binding that finds a caller with no session fresh.
     *
     * @return void
     */
    public function testCatchesABindingThatFindsASessionlessCallerFresh(): void
    {
        $this->flaw = 'sessionless';

        $this->expectException(AssertionFailedError::class);

        $this->testFreshnessFindsAnUnjudgeableCallerStale();
    }

    /**
     * The kit accepts a caller with no session as fresh from a binding that
     * does not judge sessions.
     *
     * @return void
     */
    public function testAcceptsASessionlessCallerFromABindingThatDoesNotJudgeSessions(): void
    {
        $this->flaw   = 'sessionless';
        $this->judges = false;

        $this->testFreshnessFindsAnUnjudgeableCallerStale();
    }

    /**
     * The kit fails a binding that keeps its own maximum age.
     *
     * @return void
     */
    public function testCatchesABindingThatIgnoresTheMaximumAge(): void
    {
        $this->flaw = 'age';

        $this->expectException(AssertionFailedError::class);

        $this->testFreshnessIsFreshOnlyWithinTheMaximumAge();
    }

    /**
     * The kit fails a binding that answers otherwise inside a transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatAnswersOtherwiseInsideATransaction(): void
    {
        $this->flaw = 'transaction';

        $this->expectException(AssertionFailedError::class);

        $this->testFreshnessAnswersTheSameInsideATransaction();
    }

    /**
     * The kit asks inside a transaction on the storage connection when that is
     * not the default one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAsksInsideATransactionOnTheStorageConnection(): void
    {
        config()->set('sso.storage.connection', self::STORE);

        $this->flaw = 'transaction';

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Inside the transaction each caller must get the same answer.');

        $this->testFreshnessAnswersTheSameInsideATransaction();
    }

    /**
     * A binding judging the sessions held, broken as the test says.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\Freshness
     */
    #[\Override]
    protected function freshness(): Freshness
    {
        return new readonly class (fn (): array => $this->sessions, $this->flaw) implements Freshness {
            /**
             * Constructor.
             *
             * @param  \Closure(): array<string, array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: \Carbon\CarbonImmutable}>  $sessions
             * @param  ?string  $flaw
             */
            public function __construct(

                /** Each session's identity and authentication time, as they are now. */
                private \Closure $sessions,

                /** How the binding breaks the contract, if it does. */
                private ?string $flaw,
            ) {}

            /**
             * Fresh when the caller's own session authenticated within the age.
             *
             * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
             * @param  int  $maxAgeSeconds
             * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
             * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
             */
            #[\Override]
            public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome
            {
                unset($operation);

                if ($caller === null && $this->flaw === 'no-caller') {
                    return FreshnessOutcome::FRESH;
                }

                [$identity, $at] = $this->flaw === 'sessionless' && $caller !== null && $caller->sessionId === null
                    ? [$caller->identity, CarbonImmutable::now()]
                    : ($this->sessions)()[$caller->sessionId ?? ''] ?? [null, null];

                $maxAge = match (true) {
                    $this->flaw === 'age'                                                                              => 300,
                    $this->flaw === 'transaction' && DB::connection(StorageConnection::name())->transactionLevel() > 0 => 0,
                    default                                                                                            => $maxAgeSeconds,
                };

                $owned = $identity !== null && ($this->flaw === 'identity' || $caller?->identity->is($identity) === true);

                return $owned && $at !== null && $at->diffInSeconds(CarbonImmutable::now()) <= $maxAge ? FreshnessOutcome::FRESH : FreshnessOutcome::STALE;
            }
        };
    }

    /**
     * Add the second connection: the storage connection's configuration under
     * another name.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::STORE, config('database.connections.testing'));
    }

    /**
     * @return bool
     */
    protected function judgesSessions(): bool
    {
        return $this->judges ?? $this->judgesSessionsByDefault();
    }

    /**
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    #[\Override]
    protected function freshnessOperation(): FreshnessOperation
    {
        return FreshnessOperation::CONNECTION_TRUST;
    }

    /**
     * @param  int  $seconds
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    #[\Override]
    protected function callerAuthenticatedSecondsAgo(int $seconds): Caller
    {
        $session  = 'session-' . count($this->sessions);
        $identity = new IdentityReference('App\Models\User', '1');

        $this->sessions[$session] = [$identity, CarbonImmutable::now()->subSeconds($seconds)];

        return new Caller($identity, $session);
    }

    /**
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    #[\Override]
    protected function otherIdentitysSession(): Caller
    {
        $this->sessions['session-of-2'] = [new IdentityReference('App\Models\User', '2'), CarbonImmutable::now()];

        return new Caller(new IdentityReference('App\Models\User', '1'), 'session-of-2');
    }
}
