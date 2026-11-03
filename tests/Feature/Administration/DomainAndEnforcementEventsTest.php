<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Administration\EnforcementEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\DomainLapsed;
use SineMacula\Laravel\Sso\Events\DomainRecheckFailed;
use SineMacula\Laravel\Sso\Events\DomainRestored;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesEnforcement;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the reporters of the scheduled domain checks and of
 * enforcement (SSO-3.3, SSO-4.4, SSO-4.5, SSO-10.3, SSO-10.4, SSO-10.5), whose
 * helpers arrive with the recheck and enforcement items: each event built
 * through the one projection with what it concerns and nothing more, a recheck
 * with no acting identity, an enforcement change's connections in id order, an
 * exemption's context naming the enforcing and the active tenant, and each
 * dispatched only once the storage connection's transaction commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainEvents::class)]
#[CoversClass(EnforcementEvents::class)]
final class DomainAndEnforcementEventsTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesEnforcement, UsesFlowTables;

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
        $this->createDomainsTable();
        $this->createFlowTables();
        $this->createEnforcementTable();
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
        $this->dropEnforcementTable();
        $this->dropFlowTables();
        $this->dropDomainsTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A failed recheck, a restoration and a lapse are each reported with the
     * connection, its tenant and protocol and no acting identity; a failed
     * recheck carries the failure and the lapse time the row holds.
     *
     * @return void
     */
    public function testReportsTheScheduledChecks(): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2']);
        $domain     = $this->makeDomain($connection, 'example.com', ['state' => DomainState::VERIFIED, 'lapses_at' => CarbonImmutable::parse('2026-11-04T09:30:00Z')]);
        $events     = $this->reporter(DomainEvents::class);

        $events->recheckFailed($connection, $domain, RecheckFailure::RECORD_ABSENT);
        $events->restored($connection, $domain);
        $events->lapsed($connection, $domain);

        $this->assertEventSequence([DomainRecheckFailed::class, DomainRestored::class, DomainLapsed::class]);

        [$failed, $restored, $lapsed] = $this->recordedEvents();

        self::assertInstanceOf(DomainRecheckFailed::class, $failed);
        self::assertSame(RecheckFailure::RECORD_ABSENT, $failed->failure);
        self::assertSame('2026-11-04T09:30:00+00:00', $failed->lapsesAt?->toAtomString());
        self::assertInstanceOf(DomainRestored::class, $restored);
        self::assertSame('2026-11-01T09:30:00+00:00', $restored->verifiedAt->toAtomString());
        self::assertSame('2026-11-01T09:30:00+00:00', $restored->checkedAt->toAtomString());

        foreach ([$failed, $restored, $lapsed] as $event) {
            self::assertSame($connection->id, $event->context()->connectionId);
            self::assertSame('tenant-1', $event->context()->connectionTenantId);
            self::assertSame('saml2', $event->context()->protocol);
            self::assertNull($event->context()->actingIdentityId);
            self::assertStringNotContainsString($domain->verification_token, serialize($event));
        }
    }

    /**
     * An enforcement change reports the row as it is, its connections each once
     * in id order, the version it replaced, and the acting identity.
     *
     * @return void
     */
    public function testReportsAnEnforcementChange(): void
    {
        $row = $this->makeEnforcement(['enabled' => true, 'connection_ids' => ['c-2', 'c-1', 'c-2'], 'version' => '01jbversion000000000000002']);

        $this->reporter(EnforcementEvents::class)->changed($row, '01jbversion000000000000001', new ActingIdentity('App\Models\User', '42'));

        $this->assertEventSequence([EnforcementChanged::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(EnforcementChanged::class, $event);
        self::assertTrue($event->enabled);
        self::assertSame(['c-1', 'c-2'], $event->connectionIds);
        self::assertSame('01jbversion000000000000002', $event->version);
        self::assertSame('01jbversion000000000000001', $event->previousVersion);
        self::assertSame('tenant-1', $event->context->connectionTenantId);
        self::assertSame('42', $event->context->actingIdentityId);
        self::assertNull($event->context->connectionId);
    }

    /**
     * An exemption used names the enforcing tenant, the tenant the session is
     * active in, the application, the identity, the session and the version.
     *
     * @return void
     */
    public function testReportsAnExemptionUsed(): void
    {
        $policy = EnforcementPolicy::required('child-1', 'parent-1', ['c-1'], '01jbversion000000000000003');

        $this->reporter(EnforcementEvents::class)->exemptionUsed($policy, 'web', new IdentityReference('App\Models\User', '7'), 'session-9');

        $event = $this->recordedEvents()[0] ?? null;

        self::assertInstanceOf(ExemptionUsed::class, $event);
        self::assertSame('01jbversion000000000000003', $event->enforcementVersion);
        self::assertSame('parent-1', $event->context->connectionTenantId);
        self::assertSame('child-1', $event->context->tenantId);
        self::assertSame('web', $event->context->application);
        self::assertSame('App\Models\User', $event->context->identityMorphClass);
        self::assertSame('7', $event->context->identityId);
        self::assertSame('session-9', $event->context->sessionId);
    }

    /**
     * Each is reported only once the storage connection's transaction commits,
     * and never when it rolls back.
     *
     * @return void
     */
    public function testReportsOnlyOnceTheChangeCommits(): void
    {
        $connection = $this->makeConnection();
        $domain     = $this->makeDomain($connection, 'example.com', ['state' => DomainState::VERIFIED]);
        $events     = $this->reporter(DomainEvents::class);
        $database   = DB::connection();

        $database->beginTransaction();
        $events->lapsed($connection, $domain);
        $database->rollBack();

        $this->assertNoEvents();

        $database->transaction(function () use ($events, $connection, $domain): void {
            $events->lapsed($connection, $domain);

            $this->assertNoEvents();
        });

        $this->assertEventSequence([DomainLapsed::class]);
        self::assertSame('2026-11-01T09:30:00+00:00', CarbonImmutable::instance($this->recordedEvents()[0]->context()->occurredAt)->toAtomString());
    }

    /**
     * The reporter of the class, as the container builds it.
     *
     * @template TReporter of object
     *
     * @param  class-string<TReporter>  $class
     * @return TReporter
     */
    private function reporter(string $class): object
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make($class);
    }
}
