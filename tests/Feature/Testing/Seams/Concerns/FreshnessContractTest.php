<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing\Seams\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Sso\Contracts\Freshness;
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
    use FreshnessContract;

    /** @var array<string, array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: \Carbon\CarbonImmutable}> Each session's identity and authentication time. */
    private array $sessions = [];

    /** @var ?string How the binding breaks the contract, if it does. */
    private ?string $flaw = null;

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

                [$identity, $at] = ($this->sessions)()[$caller->sessionId ?? ''] ?? [null, null];

                $maxAge = match (true) {
                    $this->flaw === 'age'                                                     => 300,
                    $this->flaw === 'transaction' && DB::connection()->transactionLevel() > 0 => 0,
                    default                                                                   => $maxAgeSeconds,
                };

                $owned = $identity !== null && ($this->flaw === 'identity' || $caller?->identity->is($identity) === true);

                return $owned && $at !== null && $at->diffInSeconds(CarbonImmutable::now()) <= $maxAge ? FreshnessOutcome::FRESH : FreshnessOutcome::STALE;
            }
        };
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
