<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Domain;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the domain model (SSO-3.1 to SSO-3.3, SSO-11.10): its table
 * and casts, its key and clock stamps, its fixed connection and domain, its
 * token hidden from serialisation, and the predicates every later reader judges
 * a domain by: an expired claim, discovery routing until the end of a grace
 * period, and linking only with a recent successful check, never older than a
 * day, and never while suspended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Domain::class)]
#[CoversClass(DomainStanding::class)]
final class DomainTest extends TestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        $this->createConnectionTables();
        $this->createDomainsTable();
        $this->createFlowTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropFlowTables();
        $this->dropDomainsTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A claim is keyed by a lower-case ULID, stamped by the package's clock,
     * read back with its state and times cast, and its lookup name is the
     * record name under the domain.
     *
     * @return void
     */
    public function testIsKeyedStampedAndCast(): void
    {
        $claim = $this->makeDomain($this->makeConnection());
        $read  = Domain::query()->findOrFail($claim->id);

        self::assertMatchesRegularExpression('/^[0-9a-z]{26}$/', $claim->id);
        self::assertSame('sso_domains', $claim->getTable());
        self::assertSame(DomainState::PENDING, $read->state);
        self::assertInstanceOf(CarbonImmutable::class, $read->claimed_at);
        self::assertSame('2026-11-01T09:30:00+00:00', $read->created_at->toAtomString());
        self::assertSame('2026-11-08T09:30:00+00:00', $read->pending_expires_at?->toAtomString());
        self::assertSame('_sso-verification.example.com', DomainStanding::lookupName($read));
    }

    /**
     * The token is hidden from serialisation.
     *
     * @return void
     */
    public function testHidesTheToken(): void
    {
        $claim = $this->makeDomain($this->makeConnection());

        self::assertArrayNotHasKey('verification_token', $claim->toArray());
        self::assertStringNotContainsString($claim->verification_token, $claim->toJson());
    }

    /**
     * Rows of `[column, value]`: each column fixed when the claim is made.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function provideFixedColumns(): iterable
    {
        yield 'the domain' => ['domain', 'example.org'];
        yield 'the connection' => ['connection_id', '01jbotherconnection0000000'];
    }

    /**
     * A claim's connection and domain are fixed once it exists; its state is
     * not.
     *
     * @param  string  $column
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideFixedColumns')]
    public function testTheConnectionAndDomainAreFixed(string $column, string $value): void
    {
        $claim = $this->makeDomain($this->makeConnection());

        $claim->forceFill(['state' => DomainState::LAPSED])->save();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A claimed domain\'s connection and domain are fixed when it is claimed.');

        Domain::query()->findOrFail($claim->id)->forceFill([$column => $value])->save();
    }

    /**
     * A pending claim expires at its expiry, and only a pending claim does.
     *
     * @return void
     */
    public function testAPendingClaimExpiresAtItsExpiry(): void
    {
        $claim = $this->makeDomain($this->makeConnection());
        $at    = CarbonImmutable::parse('2026-11-08T09:30:00Z');

        self::assertFalse(DomainStanding::isPendingExpired($claim, $at->subSecond()));
        self::assertTrue(DomainStanding::isPendingExpired($claim, $at));

        $claim->pending_expires_at = null;

        self::assertTrue(DomainStanding::isPendingExpired($claim, $at->subYear()));

        $claim->state = DomainState::VERIFIED;

        self::assertFalse(DomainStanding::isPendingExpired($claim, $at->addYear()));
    }

    /**
     * Only a verified domain routes discovery, and only until the end of a
     * grace period, even before a recheck marks it lapsed.
     *
     * @return void
     */
    public function testRoutesOnlyWhileVerifiedAndWithinAGracePeriod(): void
    {
        $connection = $this->makeConnection();
        $now        = $this->clock->now();
        $verified   = $this->makeDomain($connection, 'example.com', ['state' => DomainState::VERIFIED]);

        self::assertFalse(DomainStanding::routes($this->makeDomain($connection, 'example.org'), $now));
        self::assertFalse(DomainStanding::routes($this->makeDomain($connection, 'example.net', ['state' => DomainState::LAPSED]), $now));
        self::assertTrue(DomainStanding::routes($verified, $now));

        $verified->lapses_at = $now->addSecond();

        self::assertTrue(DomainStanding::routes($verified, $now));
        self::assertFalse(DomainStanding::routes($verified, $now->addSecond()));
    }

    /**
     * Linking needs a verified domain, not suspended, whose last successful
     * check is within the maximum age, which is never more than a day, and not
     * in the future.
     *
     * @return void
     */
    public function testAllowsLinkingOnlyWithARecentCheckAndNoSuspension(): void
    {
        $now    = $this->clock->now();
        $domain = $this->makeDomain($this->makeConnection(), 'example.com', ['state' => DomainState::VERIFIED]);

        self::assertTrue(DomainStanding::allowsLinking($domain, $now, 86400));
        self::assertTrue(DomainStanding::allowsLinking($domain, $now->addDay(), 86400));
        self::assertFalse(DomainStanding::allowsLinking($domain, $now->addDay()->addSecond(), 86400));
        self::assertFalse(DomainStanding::allowsLinking($domain, $now->addDay(), 3600));
        self::assertFalse(DomainStanding::allowsLinking($domain, $now->addDays(2), 172800), 'The maximum age is capped at a day.');
        self::assertFalse(DomainStanding::allowsLinking($domain, $now->subSecond(), 86400), 'A check in the future proves nothing.');

        $domain->linking_suspended_at = $now;

        self::assertFalse(DomainStanding::allowsLinking($domain, $now, 86400));

        $domain->linking_suspended_at     = null;
        $domain->last_successful_check_at = null;

        self::assertFalse(DomainStanding::allowsLinking($domain, $now, 86400));

        $domain->last_successful_check_at = $now;
        $domain->state                    = DomainState::PENDING;

        self::assertFalse(DomainStanding::allowsLinking($domain, $now, 86400));
    }
}
