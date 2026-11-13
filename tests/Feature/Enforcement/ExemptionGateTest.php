<?php

declare(strict_types = 1);

namespace Tests\Feature\Enforcement;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\EnforcementEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Enforcement\ExemptionGate;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\ListedExemption;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the exemption gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExemptionGate::class)]
#[CoversClass(EnforcementEvents::class)]
final class ExemptionGateTest extends TestCase
{
    use RecordsEventSequences;

    /** @var string The application the session is for. */
    private const string APPLICATION = 'web';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The break-glass administrator. */
    private IdentityReference $administrator;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference Anyone else. */
    private IdentityReference $member;

    /**
     * Bind a fixed clock, name the identities and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->administrator = new IdentityReference('App\Models\User', '1');
        $this->member        = new IdentityReference('App\Models\User', '2');

        $this->startRecordingEvents();
    }

    /**
     * The default contract exempts nobody, and nothing is reported.
     *
     * @return void
     */
    public function testTheDefaultExemptsNobody(): void
    {
        $outcome = $this->gate()->admit(self::required(), self::APPLICATION, $this->administrator, Clients::browser(), 'session-1');

        self::assertSame(ExemptionOutcome::NOT_EXEMPT, $outcome);
        $this->assertNoEvents();
    }

    /**
     * An exempted identity is admitted and reported once.
     *
     * @return void
     */
    public function testAnExemptionIsReportedOnceWithItsContext(): void
    {
        $exemption = new ListedExemption([$this->administrator]);
        $policy    = self::required();

        $this->app?->instance(EnforcementExemption::class, $exemption);

        $exempt = $this->gate()->admit($policy, self::APPLICATION, $this->administrator, Clients::browser(), 'session-1');
        $member = $this->gate()->admit($policy, self::APPLICATION, $this->member, Clients::browser());

        self::assertSame(ExemptionOutcome::EXEMPT, $exempt);
        self::assertSame(ExemptionOutcome::NOT_EXEMPT, $member);
        self::assertCount(2, $exemption->asked());
        self::assertSame($policy, $exemption->asked()[0]['policy']);
        self::assertSame(self::APPLICATION, $exemption->asked()[0]['application']);

        $this->assertEventSequence([ExemptionUsed::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(ExemptionUsed::class, $event);
        self::assertSame($policy->version, $event->enforcementVersion);
        self::assertSame('parent', $event->context->connectionTenantId);
        self::assertSame('child', $event->context->tenantId);
        self::assertSame(self::APPLICATION, $event->context->application);
        self::assertSame('App\Models\User', $event->context->identityMorphClass);
        self::assertSame('1', $event->context->identityId);
        self::assertSame('session-1', $event->context->sessionId);
        self::assertNull($event->context->connectionId);
    }

    /**
     * A policy that requires nothing asks the contract nothing.
     *
     * @return void
     */
    public function testAPolicyThatRequiresNothingAsksNothing(): void
    {
        $exemption = new ListedExemption([$this->administrator]);

        $this->app?->instance(EnforcementExemption::class, $exemption);

        $outcome = $this->gate()->admit(
            EnforcementPolicy::notRequired('child', 'parent', '01jbversionversionversion0'),
            self::APPLICATION,
            $this->administrator,
            Clients::browser(),
        );

        self::assertSame(ExemptionOutcome::NOT_EXEMPT, $outcome);
        self::assertSame([], $exemption->asked());
        $this->assertNoEvents();
    }

    /**
     * In a storage transaction the exemption is reported only once it commits.
     *
     * @return void
     */
    public function testTheExemptionIsReportedAfterCommit(): void
    {
        $this->app?->instance(EnforcementExemption::class, new ListedExemption([$this->administrator]));

        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        self::assertSame(ExemptionOutcome::EXEMPT, $this->gate()->admit(self::required(), self::APPLICATION, $this->administrator, Clients::browser()));

        $database->rollBack();

        $this->assertNoEvents();

        $database->transaction(function (): void {

            self::assertSame(ExemptionOutcome::EXEMPT, $this->gate()->admit(self::required(), self::APPLICATION, $this->administrator, Clients::browser()));

            $this->assertNoEvents();
        });

        $this->assertEventSequence([ExemptionUsed::class]);
    }

    /**
     * An exception from the contract propagates and nothing is reported.
     *
     * @return void
     */
    public function testAContractThatCannotAnswerPropagates(): void
    {
        $this->app?->instance(EnforcementExemption::class, new class implements EnforcementExemption {
            /**
             * Fail to answer.
             *
             * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
             * @param  string  $application
             * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
             * @return \SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function exemption(EnforcementPolicy $policy, string $application, IdentityReference $identity): ExemptionOutcome
            {
                throw new \RuntimeException('The exemptions cannot be read.');
            }
        });

        try {
            $this->gate()->admit(self::required(), self::APPLICATION, $this->administrator, Clients::browser());
            self::fail('The gate answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The exemptions cannot be read.', $exception->getMessage());
        }

        $this->assertNoEvents();
    }

    /**
     * An empty application is the caller's mistake.
     *
     * @return void
     */
    public function testAnEmptyApplicationIsAnInvalidArgument(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->gate()->admit(self::required(), '', $this->administrator, Clients::browser());
    }

    /**
     * The exemption gate, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\ExemptionGate
     */
    private function gate(): ExemptionGate
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ExemptionGate::class);
    }

    /**
     * A required policy of a child tenant inheriting its parent's rule.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
     */
    private static function required(): EnforcementPolicy
    {
        return EnforcementPolicy::required('child', 'parent', ['01jbconnectionconnection00'], '01jbversionversionversion0');
    }
}
