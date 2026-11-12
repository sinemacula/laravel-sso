<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * A test freshness contract that answers as told and records every question. It
 * judges no caller, so it never belongs in production.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeFreshness implements Freshness
{
    /** @var array<string, \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation> The operations that always answer `stale`, by name. */
    private array $staleOperations = [];

    /** @var list<array{operation: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation, max_age_seconds: int, caller: ?\SineMacula\Laravel\Sso\Identities\Caller}> Every question asked, in order. */
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
     * Answer `stale` for these operations and `fresh` for every other; calls
     * accumulate.
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
     * Every question asked, in order.
     *
     * @return list<array{operation: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation, max_age_seconds: int, caller: ?\SineMacula\Laravel\Sso\Identities\Caller}>
     */
    public function asked(): array
    {
        return $this->asked;
    }

    /**
     * Assert that the operation was asked about, with the maximum age if given.
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
     * Assert that exactly these operations were asked about, in order.
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
     * Assert that the operation, or with none given anything, was never asked.
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
     * The name of each operation asked, in order.
     *
     * @return list<string>
     */
    private function askedNames(): array
    {
        return array_map(static fn (FreshnessOperation $operation): string => $operation->value, array_column($this->asked, 'operation'));
    }
}
