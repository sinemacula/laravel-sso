<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Illuminate\Database\UniqueConstraintViolationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Enforcement\TenantHash;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the enforcement model (SSO-4.1, SSO-4.6, SSO-11.10): its
 * table and casts, its key and clock stamps, its tenant hash set from the
 * tenant id as the row is created, one row per tenant kept by the hash whatever
 * the collation, and a tenant fixed once the row exists.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantEnforcement::class)]
#[CoversClass(TenantHash::class)]
final class TenantEnforcementTest extends TestCase
{
    use UsesEnforcement;

    /**
     * Bind a fixed clock and create the table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->createEnforcementTable();
    }

    /**
     * Drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropEnforcementTable();

        parent::tearDown();
    }

    /**
     * A row is keyed, stamped, hashed by its tenant and read back cast.
     *
     * @return void
     */
    public function testIsKeyedStampedHashedAndCast(): void
    {
        $row  = $this->makeEnforcement(['enabled' => true, 'connection_ids' => ['c-2', 'c-1']]);
        $read = TenantEnforcement::query()->findOrFail($row->id);

        self::assertSame('sso_enforcement', $row->getTable());
        self::assertSame(hash('sha256', 'tenant-1'), $read->tenant_hash);
        self::assertSame(TenantHash::of('tenant-1'), $read->tenant_hash);
        self::assertTrue($read->enabled);
        self::assertEqualsCanonicalizing(['c-1', 'c-2'], $read->connection_ids);
        self::assertSame('2026-11-01T09:30:00+00:00', $read->changed_at?->toAtomString());
        self::assertSame('2026-11-01T09:30:00+00:00', $read->created_at->toAtomString());
    }

    /**
     * Tenants whose ids differ only in case or trailing space have rows of
     * their own; a second row for one tenant is refused.
     *
     * @return void
     */
    public function testKeepsOneRowPerTenantByItsExactId(): void
    {
        $this->makeEnforcement(['tenant_id' => 'acme']);
        $this->makeEnforcement(['tenant_id' => 'Acme']);
        $this->makeEnforcement(['tenant_id' => 'acme ']);

        self::assertSame(3, TenantEnforcement::query()->count());

        $this->expectException(UniqueConstraintViolationException::class);

        $this->makeEnforcement(['tenant_id' => 'acme']);
    }

    /**
     * Rows of `[column, value]`: each column fixed when the row is created.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function provideFixedColumns(): iterable
    {
        yield 'the tenant' => ['tenant_id', 'tenant-2'];
        yield 'the tenant hash' => ['tenant_hash', str_repeat('0', 64)];
    }

    /**
     * The tenant and its hash are fixed once the row exists; whether it is on
     * is not.
     *
     * @param  string  $column
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideFixedColumns')]
    public function testTheTenantIsFixed(string $column, string $value): void
    {
        $row = $this->makeEnforcement();

        $row->forceFill(['enabled' => true])->save();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A tenant\'s enforcement belongs to the tenant it was created for.');

        TenantEnforcement::query()->findOrFail($row->id)->forceFill([$column => $value])->save();
    }
}
