<?php

declare(strict_types = 1);

namespace Tests\Unit\Handoffs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\Enums\RedemptionStatus;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Unit tests for how a redemption ended: redeemed with the result and what the
 * code was bound to, refused for its reason, or rate limited with its wait;
 * each outcome's predicates; and that no dump, `json_encode()` or serialisation
 * shows the result's subject or attributes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RedemptionResult::class)]
#[CoversClass(RedemptionStatus::class)]
final class RedemptionResultTest extends TestCase
{
    /**
     * Each outcome is named by a stable value, in order.
     *
     * @return void
     */
    public function testEachStatusHasAStableValue(): void
    {
        self::assertSame(['redeemed', 'refused', 'rate_limited'], array_map(static fn (RedemptionStatus $status): string => $status->value, RedemptionStatus::cases()));
    }

    /**
     * A redeemed answer carries the result and everything the code was bound
     * to, and no reason or wait.
     *
     * @return void
     */
    public function testARedeemedAnswer(): void
    {
        $result   = ExampleResults::full(Purpose::REAUTHENTICATE);
        $linked   = new IdentityReference('App\Models\User', '42');
        $identity = new IdentityReference('App\Models\User', '7');
        $deadline = CarbonImmutable::parse('2026-11-01T18:00:00Z');
        $answer   = RedemptionResult::redeemed($result, $linked, $identity, 'session-1', 'version-1', $deadline);

        self::assertSame(RedemptionStatus::REDEEMED, $answer->status);
        self::assertTrue($answer->isRedeemed());
        self::assertFalse($answer->isRefused());
        self::assertFalse($answer->isRateLimited());
        self::assertNull($answer->reason);
        self::assertNull($answer->retryAfter);
        self::assertSame($result, $answer->result);
        self::assertSame($linked, $answer->linkedIdentity);
        self::assertSame($identity, $answer->identity);
        self::assertSame('session-1', $answer->sessionId);
        self::assertSame('version-1', $answer->enforcementVersion);
        self::assertSame($deadline, $answer->sessionNotAfter);
    }

    /**
     * A redeemed answer of an unlinked `sign_in` carries the result alone.
     *
     * @return void
     */
    public function testARedeemedAnswerNeedsOnlyTheResult(): void
    {
        $result = ExampleResults::bare();
        $answer = RedemptionResult::redeemed($result);

        self::assertSame(RedemptionStatus::REDEEMED, $answer->status);
        self::assertTrue($answer->isRedeemed());
        self::assertSame($result, $answer->result);
        self::assertNull($answer->linkedIdentity);
        self::assertNull($answer->identity);
        self::assertNull($answer->sessionId);
        self::assertNull($answer->enforcementVersion);
        self::assertNull($answer->sessionNotAfter);
    }

    /**
     * Every reason a redemption is refused with.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function refusals(): iterable
    {
        $reasons = [
            FailureReason::HANDOFF_UNKNOWN,
            FailureReason::HANDOFF_EXPIRED,
            FailureReason::REPLAYED,
            FailureReason::PURPOSE_MISMATCH,
            FailureReason::APPLICATION_MISMATCH,
            FailureReason::CONNECTION_MISMATCH,
            FailureReason::VERIFIER_MISMATCH,
            FailureReason::CONNECTION_UNAVAILABLE,
            FailureReason::ENFORCEMENT_UNSATISFIED,
            FailureReason::LINK_CHANGED,
        ];

        foreach ($reasons as $reason) {
            yield $reason->value => [$reason];
        }
    }

    /**
     * A refused answer carries its reason, and nothing else.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('refusals')]
    public function testARefusedAnswer(FailureReason $reason): void
    {
        $answer = RedemptionResult::refused($reason);

        self::assertSame(RedemptionStatus::REFUSED, $answer->status);
        self::assertFalse($answer->isRedeemed());
        self::assertTrue($answer->isRefused());
        self::assertFalse($answer->isRateLimited());
        self::assertSame($reason, $answer->reason);
        self::assertNull($answer->retryAfter);
        self::assertNull($answer->result);
        self::assertNull($answer->linkedIdentity);
        self::assertNull($answer->identity);
        self::assertNull($answer->sessionId);
        self::assertNull($answer->enforcementVersion);
        self::assertNull($answer->sessionNotAfter);
        self::assertSame([
            'status'            => 'refused',
            'reason'            => $reason->value,
            'retry_after'       => null,
            'purpose'           => null,
            'connection_id'     => null,
            'request_reference' => null,
        ], $answer->__debugInfo());
    }

    /**
     * A refusal for a full limit is answered by `rateLimited()`, with its wait.
     *
     * @return void
     */
    public function testARateLimitIsNotARefusal(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A rate limited redemption is answered by rateLimited(), with its wait.');

        RedemptionResult::refused(FailureReason::RATE_LIMITED);
    }

    /**
     * A rate limited answer carries `rate_limited` and its wait, from one
     * second.
     *
     * @return void
     */
    public function testARateLimitedAnswer(): void
    {
        $answer = RedemptionResult::rateLimited(1);

        self::assertSame(RedemptionStatus::RATE_LIMITED, $answer->status);
        self::assertFalse($answer->isRedeemed());
        self::assertFalse($answer->isRefused());
        self::assertTrue($answer->isRateLimited());
        self::assertSame(FailureReason::RATE_LIMITED, $answer->reason);
        self::assertSame(1, $answer->retryAfter);
        self::assertNull($answer->result);
        self::assertSame([
            'status'            => 'rate_limited',
            'reason'            => 'rate_limited',
            'retry_after'       => 1,
            'purpose'           => null,
            'connection_id'     => null,
            'request_reference' => null,
        ], $answer->__debugInfo());
        self::assertSame(60, RedemptionResult::rateLimited(60)->retryAfter);
    }

    /**
     * Waits under one second.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function shortWaits(): iterable
    {
        yield 'none' => [0];
        yield 'negative' => [-1];
    }

    /**
     * A wait under one second is refused.
     *
     * @param  int  $retryAfter
     * @return void
     */
    #[DataProvider('shortWaits')]
    public function testAWaitUnderOneSecondIsRefused(int $retryAfter): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A rate limited redemption waits at least one second.');

        RedemptionResult::rateLimited($retryAfter);
    }

    /**
     * A dump and `json_encode()` of a redeemed answer show its outcome, the
     * purpose, the connection and the reference, and never the subject, an
     * attribute or an identity.
     *
     * @return void
     */
    public function testARedeemedAnswerShowsNoAttributes(): void
    {
        $answer = RedemptionResult::redeemed(ExampleResults::full(), new IdentityReference('App\Models\User', '42'));
        $shown  = [
            'status'            => 'redeemed',
            'reason'            => null,
            'retry_after'       => null,
            'purpose'           => 'sign_in',
            'connection_id'     => '01jbexampleconnection00000',
            'request_reference' => ExampleResults::REFERENCE,
        ];

        self::assertSame($shown, $answer->__debugInfo());
        self::assertSame($shown, $answer->jsonSerialize());
        self::assertSame((string) json_encode($shown), json_encode($answer));

        foreach (['person@example.com', 'Subject 1', 'staff', 'Models', 'session-index-1'] as $needle) {
            self::assertStringNotContainsString($needle, print_r($answer, true));
            self::assertStringNotContainsString($needle, json_encode($answer));
        }
    }

    /**
     * It refuses to be serialised.
     *
     * @return void
     */
    public function testItCannotBeSerialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A redemption result cannot be serialised.');

        serialize(RedemptionResult::redeemed(ExampleResults::full()));
    }

    /**
     * It refuses to be unserialised.
     *
     * @return void
     */
    public function testItCannotBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A redemption result cannot be unserialised.');

        unserialize('O:' . strlen(RedemptionResult::class) . ':"' . RedemptionResult::class . '":0:{}');
    }
}
