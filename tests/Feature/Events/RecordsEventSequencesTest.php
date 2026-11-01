<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use Tests\Concerns\RecordsEventSequences;
use Tests\TestCase;

/**
 * Feature tests for the event sequence harness the flow tests use: it records
 * every package event and nothing else, in order, and its assertions hold for
 * exactly one failure event of the flow and reason named and fail otherwise.
 *
 * Marked `#[CoversNothing]` because the harness is test support, outside the
 * package source coverage is measured on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class RecordsEventSequencesTest extends TestCase
{
    use RecordsEventSequences;

    /**
     * Only package events are recorded, in the order they are dispatched: an
     * event that is not one, object or string, is not.
     *
     * @return void
     */
    public function testRecordsPackageEventsOnlyInOrder(): void
    {
        $this->startRecordingEvents();

        $failure = self::failure();
        $other   = self::otherEvent();

        Event::dispatch(new \stdClass);
        Event::dispatch($failure);
        Event::dispatch('sso.not-a-package-event');
        Event::dispatch($other);

        self::assertSame([$failure, $other], $this->recordedEvents());

        $this->assertEventSequence([FlowFailed::class, $other::class]);
    }

    /**
     * The sequence must match in order and in full.
     *
     * @return void
     */
    public function testTheSequenceMustMatchInOrderAndInFull(): void
    {
        $this->startRecordingEvents();

        $other = self::otherEvent();

        Event::dispatch(self::failure());
        Event::dispatch($other);

        $this->assertFailsAnAssertion(function () use ($other): void {
            $this->assertEventSequence([$other::class, FlowFailed::class]);
        });
        $this->assertFailsAnAssertion(function (): void {
            $this->assertEventSequence([FlowFailed::class]);
        });
    }

    /**
     * Starting again forgets what was recorded, and registers no second
     * listener: each event is recorded once.
     *
     * @return void
     */
    public function testStartingAgainRecordsAfresh(): void
    {
        $this->startRecordingEvents();

        Event::dispatch(self::failure());

        $this->startRecordingEvents();

        $this->assertNoEvents();

        Event::dispatch(self::failure());

        self::assertCount(1, $this->recordedEvents());
    }

    /**
     * One failure event of the flow and reason named passes, among other
     * package events, and is returned.
     *
     * @return void
     */
    public function testExactlyOneFailurePassesForOne(): void
    {
        $this->startRecordingEvents();

        $failure = self::failure(Flow::CALLBACK, FailureReason::NONCE_MISMATCH);

        Event::dispatch(self::otherEvent());
        Event::dispatch($failure);

        self::assertSame($failure, $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::NONCE_MISMATCH));
    }

    /**
     * No failure event fails the assertion.
     *
     * @return void
     */
    public function testExactlyOneFailureFailsForNone(): void
    {
        $this->startRecordingEvents();

        Event::dispatch(self::otherEvent());

        $this->assertFailsAnAssertion(function (): void {
            $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::NONCE_MISMATCH);
        });
    }

    /**
     * Two failure events fail the assertion, even when both are of the flow and
     * reason named.
     *
     * @return void
     */
    public function testExactlyOneFailureFailsForTwo(): void
    {
        $this->startRecordingEvents();

        Event::dispatch(self::failure(Flow::CALLBACK, FailureReason::NONCE_MISMATCH));
        Event::dispatch(self::failure(Flow::CALLBACK, FailureReason::NONCE_MISMATCH));

        $this->assertFailsAnAssertion(function (): void {
            $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::NONCE_MISMATCH);
        });
    }

    /**
     * One failure event of another flow, or another reason, fails the
     * assertion.
     *
     * @return void
     */
    public function testExactlyOneFailureFailsForAnotherFlowOrReason(): void
    {
        $this->startRecordingEvents();

        Event::dispatch(self::failure(Flow::CALLBACK, FailureReason::NONCE_MISMATCH));

        $this->assertFailsAnAssertion(function (): void {
            $this->assertExactlyOneFailure(Flow::ASSERTION, FailureReason::NONCE_MISMATCH);
        });
        $this->assertFailsAnAssertion(function (): void {
            $this->assertExactlyOneFailure(Flow::CALLBACK, FailureReason::REPLAYED);
        });
    }

    /**
     * No failure passes with only other package events recorded, and fails once
     * a failure event is.
     *
     * @return void
     */
    public function testNoFailure(): void
    {
        $this->startRecordingEvents();

        Event::dispatch(self::otherEvent());

        $this->assertNoFailure();

        Event::dispatch(self::failure());

        $this->assertFailsAnAssertion(function (): void {
            $this->assertNoFailure();
        });
    }

    /**
     * No events passes when nothing of the package was dispatched, and fails
     * once any package event is.
     *
     * @return void
     */
    public function testNoEvents(): void
    {
        $this->startRecordingEvents();

        Event::dispatch(new \stdClass);

        $this->assertNoEvents();

        Event::dispatch(self::otherEvent());

        $this->assertFailsAnAssertion(function (): void {
            $this->assertNoEvents();
        });
    }

    /**
     * Assert the harness assertion fails with PHPUnit's assertion failure.
     *
     * @param  \Closure(): void  $assertion
     * @return void
     */
    private function assertFailsAnAssertion(\Closure $assertion): void
    {
        $failed = null;

        try {
            $assertion();
        } catch (AssertionFailedError $failure) {
            $failed = $failure;
        }

        self::assertInstanceOf(AssertionFailedError::class, $failed, 'The harness assertion did not fail.');
    }

    /**
     * A failure event of the flow and reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Sso\Events\FlowFailed
     */
    private static function failure(Flow $flow = Flow::ASSERTION, FailureReason $reason = FailureReason::REPLAYED): FlowFailed
    {
        return new FlowFailed(self::context(), $flow, $reason);
    }

    /**
     * A package event that is not a failure.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SsoEvent
     */
    private static function otherEvent(): SsoEvent
    {
        return new readonly class (self::context()) implements SsoEvent {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Events\EventContext  $context
             */
            public function __construct(

                /** Who and what the event is about. */
                private EventContext $context,
            ) {}

            /**
             * Return who and what the event is about.
             *
             * @return \SineMacula\Laravel\Sso\Events\EventContext
             */
            #[\Override]
            public function context(): EventContext
            {
                return $this->context;
            }
        };
    }

    /**
     * A context naming a connection.
     *
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private static function context(): EventContext
    {
        return new EventContext(CarbonImmutable::parse('2026-10-31T12:00:00Z'), connectionId: 'conn_1');
    }
}
