<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for when what a metadata refresh applied stops being used
 * (SSO-2.8): never for a connection no refresh wrote; otherwise at the earlier
 * of its `validUntil` and its last validated fetch plus the stale limit, or the
 * `validUntil` alone with no limit; expired from that instant on; read again by
 * id for a connection given only through its contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataExpiry::class)]
final class MetadataExpiryTest extends TestCase
{
    use UsesConnections;

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
     * A connection no refresh wrote never expires, whatever its `validUntil`.
     *
     * @return void
     */
    public function testAConnectionNoRefreshWroteNeverExpires(): void
    {
        $connection = $this->saml(['metadata_valid_until' => $this->clock->now()->subYear()]);

        self::assertNull($this->expiry()->expiresAt($connection));
        self::assertFalse($this->expiry()->isExpired($connection));
    }

    /**
     * With no `validUntil`, what a refresh applied expires the stale limit
     * after its last validated fetch: not a second before, and from that
     * instant on.
     *
     * @return void
     */
    public function testExpiresTheStaleLimitAfterTheLastFetch(): void
    {
        $connection = $this->saml(['metadata_fetched_at' => $this->clock->now()]);

        self::assertSame('2026-12-01T09:30:00+00:00', $this->expiry()->expiresAt($connection)?->toIso8601String());

        $this->clock->advance(2592000 - 1);

        self::assertFalse($this->expiry()->isExpired($connection));

        $this->clock->advance(1);

        self::assertTrue($this->expiry()->isExpired($connection));
    }

    /**
     * The earlier of the `validUntil` and the stale limit decides.
     *
     * @return void
     */
    public function testTheEarlierOfValidUntilAndTheStaleLimitDecides(): void
    {
        $now = $this->clock->now();

        $sooner = $this->saml(['metadata_fetched_at' => $now, 'metadata_valid_until' => $now->addDay()]);
        $later  = $this->saml(['metadata_fetched_at' => $now, 'metadata_valid_until' => $now->addDays(40)]);

        self::assertSame('2026-11-02T09:30:00+00:00', $this->expiry()->expiresAt($sooner)?->toIso8601String());
        self::assertSame('2026-12-01T09:30:00+00:00', $this->expiry()->expiresAt($later)?->toIso8601String());
    }

    /**
     * With no stale limit, only the `validUntil` decides, and with neither
     * nothing expires.
     *
     * @return void
     */
    public function testWithNoStaleLimitOnlyValidUntilDecides(): void
    {
        config()->set('sso.metadata.stale_limit_seconds', 0);

        $now = $this->clock->now();

        $dated = $this->saml(['metadata_fetched_at' => $now, 'metadata_valid_until' => $now->addDay()]);

        self::assertSame('2026-11-02T09:30:00+00:00', $this->expiry()->expiresAt($dated)?->toIso8601String());
        self::assertNull($this->expiry()->expiresAt($this->saml(['metadata_fetched_at' => $now])));
    }

    /**
     * Rows of `[validated, valid until, stale limit, expiry, expired]`: when a
     * fetched document was validated, its `validUntil`, the stale limit, when
     * it expires and whether it has by now.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: int, 3: ?string, 4: bool}>
     */
    public static function provideValidatedDocuments(): iterable
    {
        yield from [
            'validated now'                      => ['2026-11-01T09:30:00Z', null, 2592000, '2026-12-01T09:30:00+00:00', false],
            'validated a limit less a second'    => ['2026-10-02T09:30:01Z', null, 2592000, '2026-11-01T09:30:01+00:00', false],
            'validated exactly a limit ago'      => ['2026-10-02T09:30:00Z', null, 2592000, '2026-11-01T09:30:00+00:00', true],
            'a valid until earlier, passed'      => ['2026-11-01T09:30:00Z', '2026-11-01T09:30:00Z', 2592000, '2026-11-01T09:30:00+00:00', true],
            'a valid until a second off'         => ['2026-11-01T09:30:00Z', '2026-11-01T09:30:01Z', 2592000, '2026-11-01T09:30:01+00:00', false],
            'the stale limit before valid until' => ['2026-10-02T09:30:00Z', '2027-01-01T00:00:00Z', 2592000, '2026-11-01T09:30:00+00:00', true],
            'no limit and no valid until'        => ['2025-01-01T00:00:00Z', null, 0, null, false],
        ];
    }

    /**
     * The expiry of a fetched document, as a refresh judges it at commit, is
     * the earlier of its `validUntil` and the moment it was validated plus the
     * stale limit, and it has expired from that instant on.
     *
     * @param  string  $validated
     * @param  ?string  $validUntil
     * @param  int  $limit
     * @param  ?string  $expiry
     * @param  bool  $expired
     * @return void
     */
    #[DataProvider('provideValidatedDocuments')]
    public function testADocumentExpiresFromItsValidation(string $validated, ?string $validUntil, int $limit, ?string $expiry, bool $expired): void
    {
        config()->set('sso.metadata.stale_limit_seconds', $limit);

        $until = $validUntil === null ? null : CarbonImmutable::parse($validUntil);
        $at    = CarbonImmutable::parse($validated);

        self::assertSame([$expiry, $expired], [$this->expiry()->expiryOf($until, $at)?->toIso8601String(), $this->expiry()->hasExpired($until, $at)]);
    }

    /**
     * A connection given only through its contract is read again by its id; one
     * that is gone never expires.
     *
     * @return void
     */
    public function testAConnectionGivenThroughItsContractIsReadAgain(): void
    {
        $connection = $this->saml(['metadata_fetched_at' => $this->clock->now()->subDays(31)]);

        self::assertTrue($this->expiry()->isExpired(new IdentifiedConnection($connection->id)));
        self::assertFalse($this->expiry()->isExpired(new IdentifiedConnection('01jbgoneconnection00000000')));
    }

    /**
     * The expiry, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\MetadataExpiry
     */
    private function expiry(): MetadataExpiry
    {
        return app(MetadataExpiry::class);
    }

    /**
     * A SAML connection with the attributes given.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $attributes): Connection
    {
        return $this->makeConnection(['protocol' => 'saml2', ...$attributes]);
    }
}
