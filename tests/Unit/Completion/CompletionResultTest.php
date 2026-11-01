<?php

declare(strict_types = 1);

namespace Tests\Unit\Completion;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStatus;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionStep;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;

/**
 * Unit tests for how a completion ended: each outcome with only its own
 * payload, the code never shown or serialised; and the steps of a completion,
 * in their fixed order, with the locked ones from link resolution on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionResult::class)]
#[CoversClass(CompletionStatus::class)]
#[CoversClass(CompletionStep::class)]
final class CompletionResultTest extends TestCase
{
    /**
     * A completed one carries the redirect, the delivery, the reference and the
     * handoff.
     *
     * @return void
     */
    public function testACompletedOne(): void
    {
        $reference = RequestReference::fromString(str_repeat('r', 32));
        $handoff   = new IssuedHandoff(HandoffCode::fromString(str_repeat('h', 43)), CarbonImmutable::parse('2026-11-01T10:01:00Z'));
        $result    = CompletionResult::completed('https://app.example.com/sso', HandoffDelivery::QUERY, $reference, $handoff);

        self::assertSame([true, false, false, false, false], self::predicates($result));
        self::assertSame(CompletionStatus::COMPLETED, $result->status);
        self::assertNull($result->reason);
        self::assertSame('https://app.example.com/sso', $result->redirectUri);
        self::assertSame(HandoffDelivery::QUERY, $result->delivery);
        self::assertSame($reference, $result->reference);
        self::assertSame($handoff, $result->handoff);
        self::assertNull($result->retryAfter);
        self::assertNull($result->startUrl);
        self::assertSame([
            'status'       => 'completed',
            'reason'       => null,
            'redirect_uri' => 'https://app.example.com/sso',
            'delivery'     => 'query',
            'reference'    => str_repeat('r', 32),
            'handoff'      => '[redacted]',
            'retry_after'  => null,
            'start_url'    => null,
        ], $result->__debugInfo());
        self::assertStringNotContainsString(str_repeat('h', 43), print_r($result, true));
    }

    /**
     * A failed one carries its reason and the trusted redirect, no handoff.
     *
     * @return void
     */
    public function testAFailedOne(): void
    {
        $reference = RequestReference::fromString(str_repeat('r', 32));
        $result    = CompletionResult::failed(FailureReason::SIGNATURE_INVALID, 'com.example.app:/sso', HandoffDelivery::FRAGMENT, $reference);

        self::assertSame([false, true, false, false, false], self::predicates($result));
        self::assertSame(FailureReason::SIGNATURE_INVALID, $result->reason);
        self::assertSame('com.example.app:/sso', $result->redirectUri);
        self::assertSame(HandoffDelivery::FRAGMENT, $result->delivery);
        self::assertSame($reference, $result->reference);
        self::assertNull($result->handoff);
        self::assertNull($result->__debugInfo()['handoff']);
    }

    /**
     * A rejected, rate limited or re-initiated one carries only its own part.
     *
     * @return void
     */
    public function testTheOtherOutcomes(): void
    {
        $rejected = CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN);

        self::assertSame([false, false, true, false, false], self::predicates($rejected));
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $rejected->reason);
        self::assertNull($rejected->redirectUri);
        self::assertNull($rejected->delivery);
        self::assertNull($rejected->reference);

        $limited = CompletionResult::rateLimited(1);

        self::assertSame([false, false, false, true, false], self::predicates($limited));
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(1, $limited->retryAfter);
        self::assertNull($limited->redirectUri);

        $reinitiated = CompletionResult::reinitiated('https://app.example.com/sso/start?connection=c');

        self::assertSame([false, false, false, false, true], self::predicates($reinitiated));
        self::assertSame('https://app.example.com/sso/start?connection=c', $reinitiated->startUrl);
        self::assertNull($reinitiated->reason);
        self::assertSame(['completed', 'failed', 'rejected', 'rate_limited', 'reinitiated'], array_column(CompletionStatus::cases(), 'value'));

        $this->expectExceptionObject(new \InvalidArgumentException('A rate limited completion waits at least one second.'));

        CompletionResult::rateLimited(0);
    }

    /**
     * A result cannot be serialised.
     *
     * @return void
     */
    public function testCannotBeSerialised(): void
    {
        $this->expectExceptionObject(new \LogicException('A completion result cannot be serialised.'));

        serialize(CompletionResult::rejected(FailureReason::REQUEST_UNKNOWN));
    }

    /**
     * A result cannot be unserialised.
     *
     * @return void
     */
    public function testCannotBeUnserialised(): void
    {
        $this->expectExceptionObject(new \LogicException('A completion result cannot be unserialised.'));

        unserialize('O:50:"SineMacula\Laravel\Sso\Completion\CompletionResult":0:{}');
    }

    /**
     * The steps run in this order, the locked transaction from the replay
     * recording on.
     *
     * @return void
     */
    public function testTheStepsAndTheirOrder(): void
    {
        self::assertSame([
            'correlation', 'consumption', 'validation', 'replay_recording', 'link_resolution', 'enforcement', 'domain_reservation', 'provisioning',
            'unlinked_decision', 'handoff_issuance',
        ], array_column(CompletionStep::cases(), 'value'));

        $locked = array_values(array_map(
            static fn (CompletionStep $step): string => $step->value,
            array_filter(CompletionStep::cases(), static fn (CompletionStep $step): bool => $step->isLocked()),
        ));

        self::assertSame(['replay_recording', 'link_resolution', 'enforcement', 'domain_reservation', 'provisioning', 'unlinked_decision', 'handoff_issuance'], $locked);
    }

    /**
     * The result's five predicates, in the order of the statuses.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $result
     * @return list<bool>
     */
    private static function predicates(CompletionResult $result): array
    {
        return [$result->isCompleted(), $result->isFailed(), $result->isRejected(), $result->isRateLimited(), $result->isReinitiated()];
    }
}
