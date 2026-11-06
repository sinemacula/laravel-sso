<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Domains\RecheckEntry;
use SineMacula\Laravel\Sso\Domains\RecheckReport;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Fixtures\Clients;

/**
 * Query budgets for the domain recheck (SSO-3.3, SSO-11.12). A run reads the
 * verified claims one chunk at a time, then checks each claim with the same
 * cost, whatever the outcome:
 *
 * - the lease: 1 read (the connection, locked) and 1 write (the conditional
 *   update);
 * - the result: 2 reads (the connection, then the claim, both locked) and 1
 *   write (the claim's update, which releases the lease).
 *
 * So a confirmation, a suspension, a lapse (with no lookup) and a failed lookup
 * each cost 3 reads and 2 writes; a suspension that lapses at once with no
 * grace period one write more; a claim another server holds 1 read and the
 * update that leased nothing. A run adds one read per chunk: one for none to
 * `CHUNK_SIZE - 1` claims.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainRechecker::class)]
final class DomainRecheckQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesDomains;

    /** @var string The token `makeDomain()` gives a claim. */
    private const string TOKEN = 'abababababababababababababababababababababababababababababababab';

    /** @var string The record name of the default claim. */
    private const string RECORD = '_sso-verification.example.com';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver the recheck looks records up through. */
    private FakeDnsResolver $dns;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection that claimed the domains. */
    private Connection $connection;

    /**
     * Bind a fake resolver and make a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->dns = new FakeDnsResolver;

        $this->app?->instance(DnsResolver::class, $this->dns);

        $this->connection = $this->makeConnection();
    }

    /**
     * A confirmation is three reads and two writes.
     *
     * @return void
     */
    public function testAConfirmationIsThreeReadsAndTwoWrites(): void
    {
        $claim = $this->verifiedClaim();

        $this->dns->found(self::RECORD, self::TOKEN);

        self::assertSame(RecheckOutcome::CONFIRMED, $this->recheckWithin(3, 2, $claim)->outcome);
    }

    /**
     * A suspension is three reads and three writes, the deletion of its open
     * reservations among them; with no grace period, the lapse that follows
     * adds another such deletion and its own write.
     *
     * @return void
     */
    public function testASuspensionIsThreeReadsAndThreeWrites(): void
    {
        $claim = $this->verifiedClaim();

        $this->dns->absent(self::RECORD)->absent('_sso-verification.example.org');

        self::assertSame(RecheckOutcome::SUSPENDED, $this->recheckWithin(3, 3, $claim)->outcome);

        config()->set('sso.domains.recheck_grace_seconds', 0);

        self::assertSame(RecheckOutcome::LAPSED, $this->recheckWithin(3, 5, $this->verifiedClaim('example.org'))->outcome);
    }

    /**
     * A lapse at the end of the grace period is three reads and three writes,
     * with nothing looked up.
     *
     * @return void
     */
    public function testALapseIsThreeReadsAndThreeWritesWithNoLookup(): void
    {
        $now   = $this->clock->now();
        $claim = $this->verifiedClaim('example.com', [
            'linking_suspended_at' => $now->subDays(3),
            'lapses_at'            => $now->addSeconds(60),
        ]);

        self::assertSame(RecheckOutcome::LAPSED, $this->recheckWithin(3, 3, $claim)->outcome);
        $this->dns->assertNothingLookedUp();
    }

    /**
     * A failed lookup is three reads and three writes: the lease taken and
     * released.
     *
     * @return void
     */
    public function testAFailedLookupIsThreeReadsAndTwoWrites(): void
    {
        $claim = $this->verifiedClaim();

        $this->dns->failing(self::RECORD);

        self::assertSame(RecheckOutcome::LOOKUP_FAILED, $this->recheckWithin(3, 2, $claim)->outcome);
    }

    /**
     * A claim another server holds is one read and the update that leased
     * nothing.
     *
     * @return void
     */
    public function testALeasedClaimIsOneReadAndOneUpdate(): void
    {
        $claim = $this->verifiedClaim();

        Domain::query()->whereKey($claim->id)->update(['recheck_leased_until' => UtcDateTime::format(new Domain, $this->clock->now()->addHours(2))]);

        self::assertSame(RecheckOutcome::SKIPPED, $this->recheckWithin(1, 1, $claim)->outcome);
        $this->dns->assertNothingLookedUp();
    }

    /**
     * A run reads its claims one chunk at a time: one read for none, and one
     * read more than its check for a single claim.
     *
     * @return void
     */
    public function testARunReadsOneChunkAtATime(): void
    {
        $rechecker = $this->rechecker();

        $none = $this->assertQueryBudget(1, 0, static fn (): RecheckReport => $rechecker->recheckAll(Clients::browser()));

        $this->verifiedClaim();
        $this->dns->found(self::RECORD, self::TOKEN);

        $one = $this->assertQueryBudget(4, 2, static fn (): RecheckReport => $rechecker->recheckAll(Clients::browser()));

        self::assertSame([], $none->entries);
        self::assertSame(1, $one->count(RecheckOutcome::CONFIRMED));
    }

    /**
     * Check the claim, as it is stored, within the reads and writes given.
     *
     * @param  int  $reads
     * @param  int  $writes
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return \SineMacula\Laravel\Sso\Domains\RecheckEntry
     */
    private function recheckWithin(int $reads, int $writes, Domain $claim): RecheckEntry
    {
        $rechecker = $this->rechecker();
        $stored    = Domain::query()->findOrFail($claim->id);

        return $this->assertQueryBudget($reads, $writes, static fn (): RecheckEntry => $rechecker->recheck($stored, Clients::browser()));
    }

    /**
     * Make the connection's claim of the domain, verified and last checked a
     * day before the clock's now, and move the clock on an hour so the claim is
     * due.
     *
     * @param  string  $domain
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    private function verifiedClaim(string $domain = 'example.com', array $attributes = []): Domain
    {
        $dayAgo = $this->clock->now()->subDay();
        $claim  = $this->makeDomain($this->connection, $domain, $attributes + [
            'state'                    => DomainState::VERIFIED,
            'verified_at'              => $dayAgo,
            'last_successful_check_at' => $dayAgo,
        ]);

        $this->clock->advance(3600);

        return $claim;
    }

    /**
     * The recheck, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Domains\DomainRechecker
     */
    private function rechecker(): DomainRechecker
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DomainRechecker::class);
    }
}
