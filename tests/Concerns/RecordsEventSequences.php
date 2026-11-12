<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;

/**
 * Records every package event a flow dispatches, in order. Faking events after
 * recording starts replaces the dispatcher it listens on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RecordsEventSequences
{
    /** @var list<\SineMacula\Laravel\Sso\Contracts\SsoEvent> The events recorded since recording last started. */
    private array $recordedEvents = [];

    /** @var bool Whether the recording listener is registered. */
    private bool $recordingEvents = false;

    /**
     * Start recording afresh, registering the listener on first use.
     *
     * @return void
     */
    protected function startRecordingEvents(): void
    {
        $this->recordedEvents = [];

        if ($this->recordingEvents) {
            return;
        }

        $this->recordingEvents = true;

        Event::listen(SsoEvent::class, function (SsoEvent $event): void {
            $this->recordedEvents[] = $event;
        });
    }

    /**
     * The package events recorded since recording last started, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Contracts\SsoEvent>
     */
    protected function recordedEvents(): array
    {
        return $this->recordedEvents;
    }

    /**
     * Assert the events recorded are exactly these classes, in this order.
     *
     * @param  list<class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>>  $classes
     * @return void
     */
    protected function assertEventSequence(array $classes): void
    {
        $recorded = array_map(static fn (SsoEvent $event): string => $event::class, $this->recordedEvents);

        Assert::assertSame($classes, $recorded, 'The package events were not dispatched in this sequence.');
    }

    /**
     * Assert exactly one failure event was recorded, for this flow and reason.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Sso\Events\FlowFailed
     */
    protected function assertExactlyOneFailure(Flow $flow, FailureReason $reason): FlowFailed
    {
        $failures = $this->recordedFailures();

        Assert::assertCount(1, $failures, sprintf('Expected exactly one failure event, %d were dispatched.', count($failures)));

        $failure = $failures[0];

        Assert::assertSame($flow, $failure->flow, sprintf('The failure event reports the %s flow, not %s.', $failure->flow->value, $flow->value));
        Assert::assertSame($reason, $failure->reason, sprintf('The failure event reports %s, not %s.', $failure->reason->value, $reason->value));

        return $failure;
    }

    /**
     * Assert no failure event was recorded.
     *
     * @return void
     */
    protected function assertNoFailure(): void
    {
        Assert::assertSame([], $this->recordedFailures(), 'A failure event was dispatched.');
    }

    /**
     * Assert no package event was recorded.
     *
     * @return void
     */
    protected function assertNoEvents(): void
    {
        Assert::assertSame([], $this->recordedEvents, 'A package event was dispatched.');
    }

    /**
     * The failure events recorded, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Events\FlowFailed>
     */
    private function recordedFailures(): array
    {
        return array_values(array_filter($this->recordedEvents, static fn (SsoEvent $event): bool => $event instanceof FlowFailed));
    }
}
