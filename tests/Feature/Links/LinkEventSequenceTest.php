<?php

declare(strict_types = 1);

namespace Tests\Feature\Links;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkEvents;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * The event sequence of each link operation (SSO-10.3, SSO-10.5): a creation
 * reports `LinkCreated` and a removal `LinkRemoved`, each exactly once; a
 * refused creation or removal reports nothing, not even a failure event, since
 * a helper's refusal is its result.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkService::class)]
#[CoversClass(LinkEvents::class)]
final class LinkEventSequenceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the removal asks. */
    private RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection links are made through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity links are made for. */
    private IdentityReference $identity;

    /**
     * Bind the clock and the freshness contract, create the tables and a
     * connection, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, $this->freshness);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['enabled' => true]);
        $this->identity   = new IdentityReference('user', '1');

        $this->startRecordingEvents();
    }

    /**
     * A creation reports `LinkCreated`, once.
     *
     * @return void
     */
    public function testACreationReportsLinkCreated(): void
    {
        self::assertTrue($this->createLink('subject-1')->isCreated());

        $this->assertEventSequence([LinkCreated::class]);
        $this->assertNoFailure();
    }

    /**
     * A removal reports `LinkRemoved`, once.
     *
     * @return void
     */
    public function testARemovalReportsLinkRemoved(): void
    {
        $id = (string) $this->createLink('subject-1')->link?->id;

        $this->startRecordingEvents();

        self::assertTrue($this->service()->remove($this->identity, $id)->isRemoved());

        $this->assertEventSequence([LinkRemoved::class]);
        $this->assertNoFailure();
    }

    /**
     * A creation refused for a subject already linked, or for the limit,
     * reports nothing.
     *
     * @return void
     */
    public function testARefusedCreationReportsNothing(): void
    {
        $this->createLink('subject-1');
        $this->startRecordingEvents();

        self::assertTrue($this->createLink('subject-1', new IdentityReference('user', '2'))->isRefused());
        self::assertTrue($this->createLink('subject-2')->isRefused());

        $this->assertNoEvents();
    }

    /**
     * A removal refused for a link not found, or for a stale caller, reports
     * nothing.
     *
     * @return void
     */
    public function testARefusedRemovalReportsNothing(): void
    {
        $id = (string) $this->createLink('subject-1')->link?->id;

        $this->startRecordingEvents();

        self::assertTrue($this->service()->remove(new IdentityReference('user', '2'), $id)->isRefused());

        $this->freshness->answer(FreshnessOutcome::STALE);

        self::assertTrue($this->service()->remove($this->identity, $id)->isRefused());

        $this->assertNoEvents();
    }

    /**
     * Link the subject through the connection, to the identity given or the
     * test's.
     *
     * @param  string  $subject
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Links\LinkCreation
     */
    private function createLink(string $subject, ?IdentityReference $identity = null): LinkCreation
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $linkSubject = new LinkSubject('https://idp.example.com', $subject);

        return $app->make(LinkStore::class)->create($this->connection, $linkSubject, $identity ?? $this->identity, LinkOrigin::PROVISIONING);
    }

    /**
     * The link helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkService
     */
    private function service(): LinkService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(LinkService::class);
    }
}
