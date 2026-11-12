<?php

declare(strict_types = 1);

namespace Tests\Feature\Domains;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Domains\DomainSummary;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the domain summary the helpers return.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainSummary::class)]
final class DomainSummaryTest extends TestCase
{
    use UsesConnections, UsesDomains;

    /** @var string The token every claim here carries. */
    private const string TOKEN = 'abababababababababababababababababababababababababababababababab';

    /**
     * Bind a fixed clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->usePackageTables();
    }

    /**
     * Every field comes from the claim; the encoding uses snake_case and UTC
     * and holds no token.
     *
     * @return void
     */
    public function testReadsEveryFieldFromTheClaim(): void
    {
        $connection = $this->makeConnection();
        $claim      = $this->makeDomain($connection, 'example.com', [
            'state'                => DomainState::VERIFIED,
            'linking_suspended_at' => CarbonImmutable::parse('2026-11-02T09:30:00Z'),
            'lapses_at'            => CarbonImmutable::parse('2026-11-05T09:30:00Z'),
        ]);

        $summary = DomainSummary::of($claim);

        self::assertSame(self::TOKEN, $summary->verificationToken());
        self::assertTrue($summary->isVerified());
        self::assertSame([
            'id'                       => $claim->id,
            'connection_id'            => $connection->id,
            'domain'                   => 'example.com',
            'state'                    => 'verified',
            'record_name'              => '_sso-verification.example.com',
            'claimed_at'               => '2026-11-01T09:30:00Z',
            'pending_expires_at'       => null,
            'verified_at'              => '2026-11-01T09:30:00Z',
            'last_successful_check_at' => '2026-11-01T09:30:00Z',
            'linking_suspended_at'     => '2026-11-02T09:30:00Z',
            'lapses_at'                => '2026-11-05T09:30:00Z',
            'lapsed_at'                => null,
        ], $summary->jsonSerialize());
        self::assertFalse(DomainSummary::of($this->makeDomain($connection, 'example.org'))->isVerified());
    }

    /**
     * No dump, export or array cast shows the token.
     *
     * @return void
     */
    public function testNoRenderingShowsTheToken(): void
    {
        $summary = DomainSummary::of($this->makeDomain($this->makeConnection()));

        self::assertStringNotContainsString(self::TOKEN, print_r($summary, true));
        self::assertStringNotContainsString(self::TOKEN, var_export((array) $summary, true));
        self::assertStringNotContainsString(self::TOKEN, (string) json_encode($summary));
        self::assertSame('[redacted]', $summary->__debugInfo()['verification_token']);
    }

    /**
     * A summary refuses to be serialised.
     *
     * @return void
     */
    public function testRefusesToBeSerialized(): void
    {
        $summary = DomainSummary::of($this->makeDomain($this->makeConnection()));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A domain summary cannot be serialised.');

        serialize($summary);
    }

    /**
     * A summary refuses to be unserialised.
     *
     * @return void
     */
    public function testRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A domain summary cannot be unserialised.');

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(DomainSummary::class), DomainSummary::class));
    }
}
