<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * A freshness contract for tests that answers what the test gave it and records
 * every operation it is asked about, with the maximum age and the caller asked
 * for, so a test of a management helper neither authenticates a caller nor
 * depends on the default, which refuses every operation (SSO-2.12).
 *
 * Bind it in place of the package's contract with
 * `$this->app->instance(Freshness::class, $fake = FakeFreshness::fresh())`, run
 * the operation, then assert what was asked. It answers `fresh` for every
 * operation unless built with `FakeFreshness::stale()`, or told with
 * `staleFor()` which operations alone answer `stale`. It holds its answers and
 * what it was asked per instance, so a test that binds a new one starts afresh.
 * It judges no caller, answering the same for none, and never belongs in
 * production: an application binds a contract that judges the caller it is
 * given instead.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeFreshness implements Freshness
{
    /** @var array<string, \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation> The operations that answer `stale` whatever the outcome, by name. */
    private array $staleOperations = [];

    /** @var list<array{operation: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation, max_age_seconds: int, caller: ?\SineMacula\Laravel\Sso\Identities\Caller}> Every question asked, in the order it was asked. */
    private array $asked = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome  $outcome
     */
    public function __construct(

        /** The answer to every operation not named by `staleFor()`. */
        private FreshnessOutcome $outcome = FreshnessOutcome::FRESH,
    ) {}

    /**
     * A contract that answers `fresh` for every operation.
     *
     * @return self
     */
    public static function fresh(): self
    {
        return new self(FreshnessOutcome::FRESH);
    }

    /**
     * A contract that answers `stale` for every operation, as the default does.
     *
     * @return self
     */
    public static function stale(): self
    {
        return new self(FreshnessOutcome::STALE);
    }

    /**
     * Answer `stale` for the operations given and `fresh` for every other,
     * however the contract was built; a later call adds to the operations an
     * earlier one gave.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  ...$operations
     * @return self
     */
    public function staleFor(FreshnessOperation ...$operations): self
    {
        $this->outcome = FreshnessOutcome::FRESH;

        foreach ($operations as $operation) {
            $this->staleOperations[$operation->value] = $operation;
        }

        return $this;
    }

    /**
     * Record the question, then answer it.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome
    {
        $this->asked[] = ['operation' => $operation, 'max_age_seconds' => $maxAgeSeconds, 'caller' => $caller];

        return isset($this->staleOperations[$operation->value]) ? FreshnessOutcome::STALE : $this->outcome;
    }

    /**
     * Every question asked, in order: the operation, the maximum age, in
     * seconds, and the caller, `null` for none, it was asked with.
     *
     * @return list<array{operation: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation, max_age_seconds: int, caller: ?\SineMacula\Laravel\Sso\Identities\Caller}>
     */
    public function asked(): array
    {
        return $this->asked;
    }

    /**
     * Assert that the operation was asked about, with the maximum age when one
     * is given.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  ?int  $maxAgeSeconds
     * @return void
     */
    public function assertAsked(FreshnessOperation $operation, ?int $maxAgeSeconds = null): void
    {
        $matching = [];

        foreach ($this->asked as $asked) {

            if ($asked['operation'] !== $operation || ($maxAgeSeconds !== null && $asked['max_age_seconds'] !== $maxAgeSeconds)) {
                continue;
            }

            $matching[] = $asked;
        }

        $expected = $maxAgeSeconds === null ? $operation->value : sprintf('%s with a maximum age of %d seconds', $operation->value, $maxAgeSeconds);

        Assert::assertNotSame([], $matching, sprintf('Expected [%s] to be asked; it was not.', $expected));
    }

    /**
     * Assert that exactly the operations given were asked about, in that order
     * and each as many times as it is given.
     *
     * @param  list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>  $operations
     * @return void
     */
    public function assertAskedExactly(array $operations): void
    {
        $expected = array_map(static fn (FreshnessOperation $operation): string => $operation->value, $operations);

        Assert::assertSame($expected, $this->askedNames(), sprintf('Expected exactly [%s] to be asked, in order.', implode(', ', $expected)));
    }

    /**
     * Assert that the operation was never asked about, or, when none is given,
     * that nothing was.
     *
     * @param  ?\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @return void
     */
    public function assertNotAsked(?FreshnessOperation $operation = null): void
    {
        if ($operation === null) {
            Assert::assertSame([], $this->askedNames(), 'Expected nothing to be asked.');

            return;
        }

        Assert::assertNotContains($operation->value, $this->askedNames(), sprintf('Expected [%s] not to be asked; it was.', $operation->value));
    }

    /**
     * The name of each operation asked about, in order.
     *
     * @return list<string>
     */
    private function askedNames(): array
    {
        return array_map(static fn (FreshnessOperation $operation): string => $operation->value, array_column($this->asked, 'operation'));
    }
}
