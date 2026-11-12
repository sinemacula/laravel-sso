<?php

declare(strict_types = 1);

namespace Tests\Unit\Links;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkResult;
use SineMacula\Laravel\Sso\Links\LinkSummary;

/**
 * Unit tests for link removal results.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkResult::class)]
final class LinkResultTest extends TestCase
{
    /**
     * A removal carries the link as it was and no reason.
     *
     * @return void
     */
    public function testARemovalCarriesTheLink(): void
    {
        $summary = new LinkSummary(
            '01jbexamplelink00000000000',
            '01jbexampleconnection00000',
            'tenant-1',
            'oidc',
            'https://op.example.com',
            null,
            LinkState::ACTIVE,
            false,
            CarbonImmutable::parse('2026-11-01T09:30:00Z'),
        );

        $result = LinkResult::removed($summary);

        self::assertSame($summary, $result->link);
        self::assertNull($result->reason);
        self::assertTrue($result->isRemoved());
        self::assertFalse($result->isRefused());
        self::assertSame(['removed' => true, 'link' => $summary->jsonSerialize(), 'reason' => null], $result->jsonSerialize());
    }

    /**
     * Rows of `[reason]`: each reason a removal is refused for.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'link_not_found' => [FailureReason::LINK_NOT_FOUND];
        yield 'freshness_required' => [FailureReason::FRESHNESS_REQUIRED];
    }

    /**
     * A refusal carries its reason and no link.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusalCarriesItsReason(FailureReason $reason): void
    {
        $result = LinkResult::refused($reason);

        self::assertNull($result->link);
        self::assertSame($reason, $result->reason);
        self::assertFalse($result->isRemoved());
        self::assertTrue($result->isRefused());
        self::assertSame(['removed' => false, 'link' => null, 'reason' => $reason->value], $result->jsonSerialize());
    }

    /**
     * Rows of `[reason]`: reasons a removal is never refused for.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideOtherReasons(): iterable
    {
        yield 'subject_already_linked' => [FailureReason::SUBJECT_ALREADY_LINKED];
        yield 'link_limit_reached' => [FailureReason::LINK_LIMIT_REACHED];
        yield 'connection_not_found' => [FailureReason::CONNECTION_NOT_FOUND];
    }

    /**
     * Any other reason is refused as an argument.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideOtherReasons')]
    public function testAnyOtherReasonIsRefused(FailureReason $reason): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException(sprintf('A link\'s removal is not refused for [%s].', $reason->value)));

        LinkResult::refused($reason);
    }
}
