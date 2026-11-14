<?php

declare(strict_types = 1);

namespace Tests\Feature\Domains;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\DomainRemoved;
use SineMacula\Laravel\Sso\Events\DomainVerified;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Feature tests for the client context the domain helpers report.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainService::class)]
final class DomainServiceTest extends DomainServiceTestCase
{
    /** @var string The TXT record name of `example.com`'s claim. */
    private const string RECORD = '_sso-verification.example.com';

    /** @var \SineMacula\Laravel\Sso\Http\ClientContext The client every change is made for. */
    private ClientContext $client;

    /**
     * Take the client, and bind another request as the one served, which the
     * helpers must not read.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->client = new ClientContext('203.0.113.7', 'Example/1.0');

        $this->app?->instance('request', Request::create('/', 'POST', server: ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_USER_AGENT' => 'Served/1.0']));
    }

    /**
     * A claim reports `DomainClaimed` carrying the client and the acting
     * identity.
     *
     * @return void
     */
    public function testAClaimReportsTheClient(): void
    {
        $result = $this->domains()->claim(self::TENANT, $this->connection->id, 'example.com', $this->client, $this->actor);

        self::assertSame(DomainStatus::CLAIMED, $result->status);
        $this->assertEventSequence([DomainClaimed::class]);
        $this->assertCarriesTheClient($this->recordedEvents()[0], '42');
    }

    /**
     * A verification reports `DomainVerified` carrying the client and the
     * acting identity.
     *
     * @return void
     */
    public function testAVerificationReportsTheClient(): void
    {
        $this->dns->publishes(self::summaryOf($this->domains()->claim(self::TENANT, $this->connection->id, 'example.com', $this->client)));
        $this->startRecordingEvents();

        $result = $this->domains()->verify(self::TENANT, $this->connection->id, 'example.com', $this->client, $this->actor);

        self::assertSame(DomainStatus::VERIFIED, $result->status);
        $this->assertEventSequence([DomainVerified::class]);
        $this->assertCarriesTheClient($this->recordedEvents()[0], '42');
    }

    /**
     * A removal reports `DomainRemoved` with the client and no acting identity
     * when none is given.
     *
     * @return void
     */
    public function testARemovalReportsTheClient(): void
    {
        $this->domains()->claim(self::TENANT, $this->connection->id, 'example.com', $this->client);
        $this->startRecordingEvents();

        $result = $this->domains()->remove(self::TENANT, $this->connection->id, 'example.com', $this->client);

        self::assertSame(DomainStatus::REMOVED, $result->status);
        $this->assertEventSequence([DomainRemoved::class]);
        $this->assertCarriesTheClient($this->recordedEvents()[0], null);
    }

    /**
     * Each change asks freshness for its own caller and operation.
     *
     * @return void
     */
    public function testEachChangeAsksFreshnessForItsCaller(): void
    {
        $caller = new Caller(new IdentityReference('App\Models\User', '42'), 'session-1');

        $this->dns->publishes(self::summaryOf($this->domains()->claim(self::TENANT, $this->connection->id, 'example.com', $this->client, $caller)));

        self::assertSame(DomainStatus::VERIFIED, $this->domains()->verify(self::TENANT, $this->connection->id, 'example.com', $this->client, $caller)->status);
        self::assertSame(DomainStatus::REMOVED, $this->domains()->remove(self::TENANT, $this->connection->id, 'example.com', $this->client, $caller)->status);

        $verify = FreshnessOperation::DOMAIN_VERIFY;

        self::assertSame([FreshnessOperation::DOMAIN_CLAIM, $verify, $verify, FreshnessOperation::DOMAIN_REMOVE], $this->freshness->operations());
        self::assertSame([$caller, $caller, $caller, $caller], $this->freshness->callers());
        self::assertSame('42', $this->recordedEvents()[0]->context()->actingIdentityId);
    }

    /**
     * A stale caller is refused each change with `freshness_required`.
     *
     * @return void
     */
    public function testAStaleCallerIsRefusedEachChange(): void
    {
        $this->dns->publishes(self::summaryOf($this->domains()->claim(self::TENANT, $this->connection->id, 'example.com', $this->client, $this->actor)));
        $this->freshness->answer(FreshnessOutcome::STALE);
        $this->startRecordingEvents();

        $claimed  = $this->domains()->claim(self::TENANT, $this->connection->id, 'example.org', $this->client, $this->actor);
        $verified = $this->domains()->verify(self::TENANT, $this->connection->id, 'example.com', $this->client, $this->actor);
        $removed  = $this->domains()->remove(self::TENANT, $this->connection->id, 'example.com', $this->client, $this->actor);

        self::assertSame(
            [FailureReason::FRESHNESS_REQUIRED, FailureReason::FRESHNESS_REQUIRED, FailureReason::FRESHNESS_REQUIRED],
            [$claimed->reason, $verified->reason, $removed->reason],
        );
        self::assertSame(DomainState::PENDING, $this->domains()->get(self::TENANT, $this->connection->id, 'example.com')?->state);
        self::assertNull($this->domains()->get(self::TENANT, $this->connection->id, 'example.org'));
        $this->assertEventSequence([]);
    }

    /**
     * A claim of an unknown connection, or of a malformed domain, is refused
     * before anything is locked.
     *
     * @return void
     */
    public function testAClaimIsRefusedForAnUnknownConnectionOrAMalformedDomain(): void
    {
        $unknown   = $this->domains()->claim(self::TENANT, '01jbzzzzzzzzzzzzzzzzzzzzzz', 'example.com', $this->client, $this->actor);
        $malformed = $this->domains()->claim(self::TENANT, $this->connection->id, 'not a domain', $this->client, $this->actor);

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $unknown->reason);
        self::assertSame([['setting' => 'domain', 'code' => 'invalid_format']], $malformed->jsonSerialize()['violations']);
        self::assertSame([], $this->freshness->asked());
    }

    /**
     * An expired claim is refused and a verified one unchanged, neither looked
     * up.
     *
     * @return void
     */
    public function testAnExpiredOrVerifiedClaimIsJudgedWithoutALookup(): void
    {
        $this->claimDomain('example.org');
        $this->clock->advance(604800);

        $expired = $this->domains()->verify(self::TENANT, $this->connection->id, 'example.org', $this->client, $this->actor);

        $this->dns->publishes(self::summaryOf($this->claimDomain()));

        self::assertSame(DomainStatus::VERIFIED, $this->verifyDomain()->status);

        $again = $this->domains()->verify(self::TENANT, $this->connection->id, 'example.com', $this->client, $this->actor);

        self::assertSame(FailureReason::DOMAIN_CLAIM_EXPIRED, $expired->reason);
        self::assertSame(DomainStatus::UNCHANGED, $again->status);
        $this->dns->assertLookedUp(self::RECORD, 1);
    }

    /**
     * A caller found stale under the lock, though fresh before the lookup, is
     * refused and nothing is verified.
     *
     * @return void
     */
    public function testAVerificationAsksAgainUnderTheLock(): void
    {
        $this->dns->publishes(self::summaryOf($this->claimDomain()));

        $this->freshness->onCheck = function (): void {
            $this->freshness->onCheck = fn () => $this->freshness->answer(FreshnessOutcome::STALE);
        };

        $result = $this->domains()->verify(self::TENANT, $this->connection->id, 'example.com', $this->client, $this->actor);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame(DomainState::PENDING, $this->domains()->get(self::TENANT, $this->connection->id, 'example.com')?->state);
    }

    /**
     * A change for no client, as from the console, reports no IP address or
     * user agent.
     *
     * @return void
     */
    public function testAChangeForNoClientReportsNone(): void
    {
        $this->domains()->claim(self::TENANT, $this->connection->id, 'example.com', new ClientContext(null, null), $this->actor);

        $context = $this->recordedEvents()[0]->context();

        self::assertSame([null, null], [$context->ip, $context->userAgent]);
    }

    /**
     * Verifications count against the connection's domain checks, not the
     * client.
     *
     * @return void
     */
    public function testAVerificationIsCountedAgainstTheConnectionWhateverTheClient(): void
    {
        config()->set('sso.rate_limits.domain_check.per_connection', ['max' => 1, 'decay_seconds' => 3600]);

        $this->domains()->claim(self::TENANT, $this->connection->id, 'example.com', $this->client);
        $this->dns->absent(self::RECORD);

        self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $this->domains()->verify(self::TENANT, $this->connection->id, 'example.com', $this->client)->reason);

        $limited = $this->domains()->verify(self::TENANT, $this->connection->id, 'example.com', new ClientContext('198.51.100.20', 'Other/1.0'));

        self::assertTrue($limited->isRateLimited());
        $this->dns->assertLookedUp(self::RECORD, 1);
    }

    /**
     * Assert the event carries the client's address and agent, not the served
     * request's.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoEvent  $event
     * @param  ?string  $actingIdentityId
     * @return void
     */
    private function assertCarriesTheClient(SsoEvent $event, ?string $actingIdentityId): void
    {
        $context = $event->context();

        self::assertSame(['203.0.113.7', 'Example/1.0'], [$context->ip, $context->userAgent]);
        self::assertSame($actingIdentityId, $context->actingIdentityId);
        self::assertSame($this->connection->id, $context->connectionId);
    }
}
