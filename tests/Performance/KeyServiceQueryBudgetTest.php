<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Keys\Certificates;

/**
 * Query budgets for the key helpers. A change reads before freshness is asked,
 * then again under the connection's lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyService::class)]
final class KeyServiceQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections;

    /** @var string The tenant whose connection the helpers act on. */
    private const string TENANT = 'tenant-1';

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helpers ask. */
    private RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's SAML connection. */
    private Connection $connection;

    /**
     * Answer `fresh` to every freshness check and make a SAML connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;

        $this->app?->instance(Freshness::class, $this->freshness);

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);
    }

    /**
     * The connection and the use's states, twice, and the insert; the same for
     * the first key and the next.
     *
     * @return void
     */
    public function testAddingAKeyIsFourReadsAndAnInsert(): void
    {
        $first = $this->assertQueryBudget(4, 1, fn (): KeyResult => $this->add());
        $next  = $this->assertQueryBudget(4, 1, fn (): KeyResult => $this->add());

        self::assertSame(KeyState::CURRENT, $first->key?->state);
        self::assertSame(KeyState::NEXT, $next->key?->state);
    }

    /**
     * The connection and key twice and the use's current key; the current made
     * retiring and the next current.
     *
     * @return void
     */
    public function testMakingAKeyCurrentIsFiveReadsAndTwoUpdates(): void
    {
        $this->add();

        $next   = self::summaryOf($this->add());
        $result = $this->assertQueryBudget(5, 2, fn (): KeyResult => $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $next->id, Clients::browser()));

        self::assertTrue($result->isSucceeded());
    }

    /**
     * The connection and the key, twice, and the delete.
     *
     * @return void
     */
    public function testRetiringAKeyIsFourReadsAndADelete(): void
    {
        $this->add();

        $next   = self::summaryOf($this->add());
        $result = $this->assertQueryBudget(4, 1, fn (): KeyResult => $this->keys()->retire(self::TENANT, $this->connection->id, $next->id, Clients::browser()));

        self::assertTrue($result->isSucceeded());
    }

    /**
     * The connection and the trusted fingerprints, twice, and the insert; an
     * additive certificate voids nothing.
     *
     * @return void
     */
    public function testTrustingASigningCertificateIsFourReadsAndOneWrite(): void
    {
        $result = $this->assertQueryBudget(
            4,
            1,
            fn (): KeyResult => $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser()),
        );

        self::assertTrue($result->isSucceeded());
    }

    /**
     * A metadata signing anchor adds the voiding's four writes to the insert:
     * requests, codes, trust version and reservations.
     *
     * @return void
     */
    public function testTrustingAnAnchorIsFourReadsAndFiveWrites(): void
    {
        $anchor = Certificates::distinct(0);
        $result = $this->assertQueryBudget(
            4,
            5,
            fn (): KeyResult => $this->keys()->trustCertificate(self::TENANT, $this->connection->id, $anchor, Clients::browser(), null, KeyUse::METADATA_SIGNING),
        );

        self::assertTrue($result->isSucceeded());
    }

    /**
     * The connection and the key, twice, the delete and the voiding's four
     * writes.
     *
     * @return void
     */
    public function testDistrustingACertificateIsFourReadsAndFiveWrites(): void
    {
        $certificate = self::summaryOf($this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser()));
        $result      = $this->assertQueryBudget(
            4,
            5,
            fn (): KeyResult => $this->keys()->distrustCertificate(self::TENANT, $this->connection->id, $certificate->id, Clients::browser()),
        );

        self::assertTrue($result->isSucceeded());
    }

    /**
     * The connection, then its keys, however many there are.
     *
     * @return void
     */
    public function testListingTheKeysIsTwoReads(): void
    {
        $this->add();
        $this->add();
        $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser());

        $keys = $this->assertQueryBudget(2, 0, fn (): ?array => $this->keys()->keys(self::TENANT, $this->connection->id));

        self::assertCount(3, $keys ?? []);
    }

    /**
     * A stale caller costs the reads before freshness is asked, under the lock
     * but for a key's addition, and no write.
     *
     * @return void
     */
    public function testAStaleCallerCostsTheReadsBeforeFreshness(): void
    {
        $this->add();

        $next = self::summaryOf($this->add());

        $this->freshness->answer(FreshnessOutcome::STALE);

        $refusals = [
            $this->assertQueryBudget(3, 0, fn (): KeyResult => $this->keys()->makeCurrent(self::TENANT, $this->connection->id, $next->id, Clients::browser())),
            $this->assertQueryBudget(2, 0, fn (): KeyResult => $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_ENCRYPTION, Clients::browser())),
            $this->assertQueryBudget(3, 0, fn (): KeyResult => $this->keys()->trustCertificate(self::TENANT, $this->connection->id, Certificates::distinct(0), Clients::browser())),
        ];

        foreach ($refusals as $refusal) {
            self::assertSame(FailureReason::FRESHNESS_REQUIRED, $refusal->reason);
        }
    }

    /**
     * Add a P-256 signing key to the connection.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyResult
     */
    private function add(): KeyResult
    {
        return $this->keys()->addNext(self::TENANT, $this->connection->id, KeyUse::SP_SIGNING, Clients::browser(), KeyType::RSA);
    }

    /**
     * The key helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyService
     */
    private function keys(): KeyService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyService::class);
    }

    /**
     * The summary the result carries, which it must.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyResult  $result
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private static function summaryOf(KeyResult $result): KeySummary
    {
        self::assertNotNull($result->key);

        return $result->key;
    }
}
