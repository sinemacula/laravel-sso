<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\Flow;

/**
 * Unit tests for the flows a failure event reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Flow::class)]
final class FlowTest extends TestCase
{
    /**
     * The flows are fixed: a value is never renamed or reused.
     *
     * @return void
     */
    public function testTheFlowsAreStable(): void
    {
        self::assertSame([
            'AUTHORIZATION_REQUEST' => 'authorization_request',
            'ASSERTION'             => 'assertion',
            'CALLBACK'              => 'callback',
            'REDEMPTION'            => 'redemption',
        ], array_column(array_map(static fn (Flow $flow): array => ['name' => $flow->name, 'value' => $flow->value], Flow::cases()), 'value', 'name'));
    }

    /**
     * Values are American spellings; the British spelling reads as none.
     *
     * @return void
     */
    public function testEachValueReadsBackAsItsCase(): void
    {
        self::assertSame(Flow::AUTHORIZATION_REQUEST, Flow::from('authorization_request'));
        self::assertSame(Flow::ASSERTION, Flow::from('assertion'));
        self::assertSame(Flow::CALLBACK, Flow::from('callback'));
        self::assertSame(Flow::REDEMPTION, Flow::from('redemption'));
        self::assertNull(Flow::tryFrom('authorisation_request'));
    }
}
