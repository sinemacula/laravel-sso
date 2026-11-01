<?php

declare(strict_types = 1);

namespace Tests\Unit\Flows;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\StartStatus;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Flows\Verifier;
use SineMacula\Laravel\Sso\Protocols\Navigation;

/**
 * Unit tests for the answer to a start: started with its reference, navigation
 * and the verifier generated once; refused; or rate limited with its wait; each
 * answered with `Cache-Control: no-store`, the body revealing the verifier and
 * nothing else ever showing it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StartResult::class)]
#[CoversClass(StartStatus::class)]
final class StartResultTest extends TestCase
{
    /**
     * A started answer's body is the reference, the navigation and, once, the
     * generated verifier.
     *
     * @return void
     */
    public function testAStartedAnswer(): void
    {
        $reference  = RequestReference::fromString(str_repeat('r', 32));
        $navigation = Navigation::post('https://idp.example.com/sso', ['SAMLRequest' => 'abc', 'RelayState' => 'xyz']);
        $verifier   = Verifier::fromString(str_repeat('v', 43));
        $result     = StartResult::started($reference, $navigation, $verifier);

        self::assertTrue($result->isStarted());
        self::assertFalse($result->isRefused());
        self::assertFalse($result->isRateLimited());
        self::assertSame(StartStatus::STARTED, $result->status);
        self::assertSame($reference, $result->reference);
        self::assertSame($navigation, $result->navigation);
        self::assertSame($verifier, $result->verifier);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
        self::assertSame([
            'reference'  => str_repeat('r', 32),
            'navigation' => ['type' => 'post', 'url' => 'https://idp.example.com/sso', 'fields' => ['SAMLRequest' => 'abc', 'RelayState' => 'xyz']],
            'verifier'   => str_repeat('v', 43),
        ], $result->body());
        self::assertSame(['Cache-Control' => 'no-store'], $result->headers());
        self::assertSame(['Cache-Control' => 'no-store'], StartResult::HEADERS);
    }

    /**
     * A client that sent its own challenge gets no verifier back.
     *
     * @return void
     */
    public function testAStartWithTheClientsChallengeCarriesNoVerifier(): void
    {
        $result = StartResult::started(RequestReference::fromString(str_repeat('r', 32)), Navigation::redirect('https://idp.example.com/a'));

        self::assertNull($result->verifier);
        self::assertSame([
            'reference'  => str_repeat('r', 32),
            'navigation' => ['type' => 'redirect', 'url' => 'https://idp.example.com/a'],
        ], $result->body());
    }

    /**
     * A refused answer carries its reason, as its body's `error`.
     *
     * @return void
     */
    public function testARefusedAnswer(): void
    {
        $result = StartResult::refused(FailureReason::APPLICATION_NOT_ALLOWED);

        self::assertTrue($result->isRefused());
        self::assertFalse($result->isStarted());
        self::assertFalse($result->isRateLimited());
        self::assertSame(StartStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $result->reason);
        self::assertNull($result->reference);
        self::assertNull($result->navigation);
        self::assertNull($result->verifier);
        self::assertNull($result->retryAfter);
        self::assertSame(['error' => 'application_not_allowed'], $result->body());
        self::assertSame(['Cache-Control' => 'no-store'], $result->headers());

        $this->expectExceptionObject(new \InvalidArgumentException('A rate limited start is answered by rateLimited(), with its wait.'));

        StartResult::refused(FailureReason::RATE_LIMITED);
    }

    /**
     * A rate limited answer carries its wait, at least a second, in its body
     * and as `Retry-After`.
     *
     * @return void
     */
    public function testARateLimitedAnswer(): void
    {
        $result = StartResult::rateLimited(1);

        self::assertTrue($result->isRateLimited());
        self::assertFalse($result->isStarted());
        self::assertFalse($result->isRefused());
        self::assertSame(StartStatus::RATE_LIMITED, $result->status);
        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
        self::assertSame(1, $result->retryAfter);
        self::assertSame(['error' => 'rate_limited', 'retry_after' => 1], $result->body());
        self::assertSame(['Cache-Control' => 'no-store', 'Retry-After' => '1'], $result->headers());
        self::assertSame(['started', 'refused', 'rate_limited'], array_column(StartStatus::cases(), 'value'));

        $this->expectExceptionObject(new \InvalidArgumentException('A rate limited start waits at least one second.'));

        StartResult::rateLimited(0);
    }

    /**
     * A dump never shows the verifier, and the answer cannot be serialised.
     *
     * @return void
     */
    public function testNeverShowsTheVerifier(): void
    {
        $reference = RequestReference::fromString(str_repeat('r', 32));
        $result    = StartResult::started($reference, Navigation::redirect('https://idp.example.com/a'), Verifier::fromString(str_repeat('v', 43)));

        self::assertSame([
            'status'      => 'started',
            'reference'   => str_repeat('r', 32),
            'navigation'  => ['type' => 'redirect', 'url' => 'https://idp.example.com/a'],
            'verifier'    => '[redacted]',
            'reason'      => null,
            'retry_after' => null,
        ], $result->__debugInfo());
        self::assertStringNotContainsString(str_repeat('v', 43), print_r($result, true));
        self::assertNull(StartResult::rateLimited(5)->__debugInfo()['verifier']);

        $this->expectExceptionObject(new \LogicException('A start result cannot be serialised.'));

        serialize($result);
    }

    /**
     * An answer cannot be unserialised.
     *
     * @return void
     */
    public function testCannotBeUnserialised(): void
    {
        $this->expectExceptionObject(new \LogicException('A start result cannot be unserialised.'));

        unserialize('O:40:"SineMacula\Laravel\Sso\Flows\StartResult":0:{}');
    }
}
