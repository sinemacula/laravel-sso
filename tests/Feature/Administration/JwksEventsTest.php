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
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the JWKS refetch event reporter.
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

        $this->usePackageTables();
        $this->startRecordingEvents();
    }

    /**
     * A refetch and a failed one are reported with the connection and no acting
     * identity.
     *
     * @return void
     */
    public function testReportsARefetchAndAFailure(): void
    {
        $connection = $this->makeConnection(['protocol' => 'oidc', 'jwks' => '[{"kty":"RSA","kid":"secret-kid"}]', 'jwks_version' => 3]);
        $events     = app(JwksEvents::class);

        $events->refreshed($connection, 2, 1, true, Clients::browser());
        $events->refreshFailed($connection, FailureReason::JWKS_INVALID, CarbonImmutable::parse('2026-11-01T11:35:00+02:00'), Clients::browser());

        $this->assertEventSequence([JwksRefreshed::class, JwksRefreshFailed::class]);

        [$refreshed, $failed] = $this->recordedEvents();

        self::assertInstanceOf(JwksRefreshed::class, $refreshed);
        self::assertSame([3, 2, 1, true], [$refreshed->jwksVersion, $refreshed->keysAdded, $refreshed->keysRemoved, $refreshed->trustChanged]);
        self::assertInstanceOf(JwksRefreshFailed::class, $failed);
        self::assertSame(FailureReason::JWKS_INVALID, $failed->reason);
        self::assertSame('2026-11-01T09:35:00+00:00', $failed->nextRefetchAt?->toAtomString());

        foreach ([$refreshed, $failed] as $event) {
            $context = $event->context();

            self::assertSame([$connection->id, 'tenant-1', 'oidc', null], [$context->connectionId, $context->connectionTenantId, $context->protocol, $context->actingIdentityId]);
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
        app(JwksEvents::class)->refreshFailed($this->makeConnection(['protocol' => 'oidc']), FailureReason::FETCH_FAILED, null, Clients::browser());

        $event = $this->recordedEvents()[0] ?? null;

        self::assertInstanceOf(JwksRefreshFailed::class, $event);
        self::assertNull($event->nextRefetchAt);
    }

    /**
     * Each is reported once the transaction commits, never on rollback.
     *
     * @return void
     */
    public function testReportsOnlyOnceTheRefetchCommits(): void
    {
        $connection = $this->makeConnection(['protocol' => 'oidc', 'jwks_version' => 1]);
        $events     = app(JwksEvents::class);
        $database   = DB::connection();

        $database->beginTransaction();
        $events->refreshed($connection, 1, 0, false, Clients::browser());
        $database->rollBack();

        $this->assertNoEvents();

        $database->transaction(function () use ($events, $connection): void {
            $events->refreshed($connection, 1, 0, false, Clients::browser());

            $this->assertNoEvents();
        });

        $this->assertEventSequence([JwksRefreshed::class]);
    }
}
