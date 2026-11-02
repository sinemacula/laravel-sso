<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\JwksEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\JwksRefreshed;
use SineMacula\Laravel\Sso\Events\JwksRefreshFailed;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the reporter of a JWKS refetch on an unknown `kid`
 * (SSO-7.3, SSO-10.3, SSO-10.4, SSO-10.5): each event built through the one
 * projection with the connection, its tenant and protocol and no acting
 * identity, the version as the row holds it, the next refetch in UTC, nothing
 * of the keys, and each dispatched only once the storage connection's
 * transaction commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwksEvents::class)]
final class JwksEventsTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /**
     * Bind a fixed clock, create the tables and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->createConnectionTables();
        $this->startRecordingEvents();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A refetch and a failed one are reported with the connection, its tenant
     * and protocol, no acting identity, and what each concerns.
     *
     * @return void
     */
    public function testReportsARefetchAndAFailure(): void
    {
        $connection = $this->makeConnection(['protocol' => 'oidc', 'jwks' => '[{"kty":"RSA","kid":"secret-kid"}]', 'jwks_version' => 3]);
        $events     = app(JwksEvents::class);

        $events->refreshed($connection, 2, 1, true);
        $events->refreshFailed($connection, FailureReason::JWKS_INVALID, CarbonImmutable::parse('2026-11-01T11:35:00+02:00'));

        $this->assertEventSequence([JwksRefreshed::class, JwksRefreshFailed::class]);

        [$refreshed, $failed] = $this->recordedEvents();

        self::assertInstanceOf(JwksRefreshed::class, $refreshed);
        self::assertSame([3, 2, 1, true], [$refreshed->jwksVersion, $refreshed->keysAdded, $refreshed->keysRemoved, $refreshed->trustChanged]);
        self::assertInstanceOf(JwksRefreshFailed::class, $failed);
        self::assertSame(FailureReason::JWKS_INVALID, $failed->reason);
        self::assertSame('2026-11-01T09:35:00+00:00', $failed->nextRefetchAt?->toAtomString());

        foreach ([$refreshed, $failed] as $event) {
            $context = $event->context();

            self::assertSame([$connection->id, 'tenant-1', 'oidc', null], [$context->connectionId, $context->tenantId, $context->protocol, $context->actingIdentityId]);
            self::assertStringNotContainsString('secret-kid', serialize($event));
        }
    }

    /**
     * A failure with no next refetch carries none.
     *
     * @return void
     */
    public function testReportsAFailureWithNoNextRefetch(): void
    {
        app(JwksEvents::class)->refreshFailed($this->makeConnection(['protocol' => 'oidc']), FailureReason::FETCH_FAILED, null);

        $event = $this->recordedEvents()[0] ?? null;

        self::assertInstanceOf(JwksRefreshFailed::class, $event);
        self::assertNull($event->nextRefetchAt);
    }

    /**
     * Each is reported only once the storage connection's transaction commits,
     * and never when it rolls back.
     *
     * @return void
     */
    public function testReportsOnlyOnceTheRefetchCommits(): void
    {
        $connection = $this->makeConnection(['protocol' => 'oidc', 'jwks_version' => 1]);
        $events     = app(JwksEvents::class);
        $database   = DB::connection();

        $database->beginTransaction();
        $events->refreshed($connection, 1, 0, false);
        $database->rollBack();

        $this->assertNoEvents();

        $database->transaction(function () use ($events, $connection): void {
            $events->refreshed($connection, 1, 0, false);

            $this->assertNoEvents();
        });

        $this->assertEventSequence([JwksRefreshed::class]);
    }
}
