<?php

declare(strict_types = 1);

namespace Tests\Unit\Links;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for the result of a link's creation (SSO-8.4, outcomes
 * convention): the stable statuses and the reason each refusal carries, one
 * named constructor per outcome, the predicates, and the snake_case encoding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkCreation::class)]
#[CoversClass(LinkCreationStatus::class)]
final class LinkCreationTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /**
     * The statuses are exactly these, by value, and each refusal carries its
     * own reason.
     *
     * @return void
     */
    public function testTheStatusesAndTheirReasonsAreStable(): void
    {
        self::assertSame(['created', 'subject_already_linked', 'link_limit_reached'], array_column(LinkCreationStatus::cases(), 'value'));
        self::assertNull(LinkCreationStatus::CREATED->reason());
        self::assertSame(FailureReason::SUBJECT_ALREADY_LINKED, LinkCreationStatus::SUBJECT_ALREADY_LINKED->reason());
        self::assertSame(FailureReason::LINK_LIMIT_REACHED, LinkCreationStatus::LINK_LIMIT_REACHED->reason());
    }

    /**
     * Only a creation names the link made.
     *
     * @return void
     */
    public function testOnlyACreationNamesItsLink(): void
    {
        $summary = self::summary();

        self::assertSame($summary->id, LinkCreation::created($summary)->linkId());
        self::assertNull(LinkCreation::subjectAlreadyLinked()->linkId());
        self::assertNull(LinkCreation::linkLimitReached()->linkId());
    }

    /**
     * A creation carries the link and no reason.
     *
     * @return void
     */
    public function testACreationCarriesTheLink(): void
    {
        $summary  = self::summary();
        $creation = LinkCreation::created($summary);

        self::assertSame(LinkCreationStatus::CREATED, $creation->status);
        self::assertSame($summary, $creation->link);
        self::assertNull($creation->reason());
        self::assertTrue($creation->isCreated());
        self::assertFalse($creation->isRefused());
        self::assertSame(['status' => 'created', 'link' => $summary->jsonSerialize(), 'reason' => null], $creation->jsonSerialize());
    }

    /**
     * Each refusal carries its reason and no link.
     *
     * @return void
     */
    public function testEachRefusalCarriesItsReason(): void
    {
        $cases = [
            [LinkCreation::subjectAlreadyLinked(), LinkCreationStatus::SUBJECT_ALREADY_LINKED, FailureReason::SUBJECT_ALREADY_LINKED],
            [LinkCreation::linkLimitReached(), LinkCreationStatus::LINK_LIMIT_REACHED, FailureReason::LINK_LIMIT_REACHED],
        ];

        foreach ($cases as [$creation, $status, $reason]) {
            self::assertSame($status, $creation->status);
            self::assertNull($creation->link);
            self::assertSame($reason, $creation->reason());
            self::assertFalse($creation->isCreated());
            self::assertTrue($creation->isRefused());
            self::assertSame(['status' => $status->value, 'link' => null, 'reason' => $reason->value], $creation->jsonSerialize());
        }
    }

    /**
     * A link's summary.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkSummary
     */
    private static function summary(): LinkSummary
    {
        return new LinkSummary(
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
    }
}
