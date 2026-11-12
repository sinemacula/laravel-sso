<?php

declare(strict_types = 1);

namespace Tests\Unit\Completion\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint;
use SineMacula\Laravel\Sso\Events\Enums\Flow;

/**
 * Unit tests for the completion endpoint enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionEndpoint::class)]
final class CompletionEndpointTest extends TestCase
{
    /**
     * There are exactly two endpoints, each valued as its published endpoint.
     *
     * @return void
     */
    public function testTheCasesAreTheTwoCompletionEndpoints(): void
    {
        self::assertSame(['assertion_consumer_service', 'callback'], array_column(CompletionEndpoint::cases(), 'value'));
        self::assertSame(Endpoint::ASSERTION_CONSUMER_SERVICE->value, CompletionEndpoint::ASSERTION_CONSUMER_SERVICE->value);
        self::assertSame(Endpoint::CALLBACK->value, CompletionEndpoint::CALLBACK->value);
    }

    /**
     * The assertion consumer service reports `assertion` and takes `POST`.
     *
     * @return void
     */
    public function testTheAssertionConsumerService(): void
    {
        self::assertSame(Flow::ASSERTION, CompletionEndpoint::ASSERTION_CONSUMER_SERVICE->flow());
        self::assertSame('POST', CompletionEndpoint::ASSERTION_CONSUMER_SERVICE->method());
    }

    /**
     * The callback reports `callback` and takes `GET`.
     *
     * @return void
     */
    public function testTheCallback(): void
    {
        self::assertSame(Flow::CALLBACK, CompletionEndpoint::CALLBACK->flow());
        self::assertSame('GET', CompletionEndpoint::CALLBACK->method());
    }
}
