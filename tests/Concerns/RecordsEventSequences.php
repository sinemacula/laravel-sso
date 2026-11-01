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
 * Records every package event a flow dispatches, in order, so a flow test can
 * assert what it reported: the sequence of event classes, and that a refused
 * operation fired exactly one `FlowFailed` with its flow and reason (SSO-10.2).
 *
 * One listener on the `SsoEvent` contract receives every package event, since
 * Laravel dispatches an event to the listeners of the interfaces it
 * implements; an event that is not a package event is never recorded. The
 * listener is registered on the dispatcher bound when recording first starts,
 * so a test that fakes events afterwards records nothing. An event dispatched
 * after commit is recorded when it is dispatched, so a test reads the sequence
 * once the flow's transaction has ended.
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
     * Assert the events recorded are of these classes, in this order, and no
     * others.
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
     * Assert exactly one failure event was recorded, for this flow and reason,
     * and return it.
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
