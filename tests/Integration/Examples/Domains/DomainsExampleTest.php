<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Domains;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Domains\DomainResult;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\DomainSummary;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/domains.md` (SSO-3.1, SSO-3.2, SSO-12.5), on the
 * shared example harness: an administrator claiming a domain and shown the
 * record to publish, the domain verified once the record holds the token, read,
 * listed and removed, the application's own DNS over HTTPS resolver bound in
 * place of the default, and the fake resolver a test binds. Each refusal the
 * guide lists is asserted beside the example it follows: a claim of what could
 * not be registered, of a refused provider, twice, for an unknown connection,
 * by a stale caller or of a domain verified elsewhere; a verification with no
 * record, a lookup that failed, a claim that expired or none at all; and a fake
 * resolver with no answer for the name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainService::class)]
#[CoversClass(DomainResult::class)]
#[CoversClass(DomainSummary::class)]
#[CoversClass(FakeDnsResolver::class)]
final class DomainsExampleTest extends ExampleTestCase
{
    /** @var string The connection the domains are claimed for. */
    private string $connectionId;

    /** @var \Tests\Integration\Examples\Domains\User The administrator acting. */
    private User $user;

    /**
     * Make the connection and the administrator.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));
        $this->user         = new User(['id' => 'admin-1']);
    }

    /**
     * A claim stores the domain normalised and pending, answers the record name
     * and the token to publish, encodes to JSON without the token, and reports
     * the administrator by their morph class and key.
     *
     * @return void
     */
    public function testAClaimShowsTheRecordToPublish(): void
    {
        $tenantId     = self::TENANT;
        $connectionId = $this->connectionId;
        $user         = $this->user;

        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\DomainClaimed> $claims */
        $claims = new \ArrayObject;

        Event::listen(DomainClaimed::class, static function (DomainClaimed $event) use ($claims): void {
            $claims->append($event);
        });

        // @snippet-start domain-service
        $domains = app(DomainService::class);
        // @snippet-end domain-service
        // @snippet-start domain-claim
        $actor  = new ActingIdentity($user->getMorphClass(), (string) $user->getKey());
        $result = $domains->claim($tenantId, $connectionId, 'Example.COM', $actor);

        // A successful claim carries the domain; a refusal carries none
        $record = $result->domain?->recordName;          // _sso-verification.example.com
        $value  = $result->domain?->verificationToken(); // 64 lower-case hex characters
        // @snippet-end domain-claim
        self::assertSame(DomainStatus::CLAIMED, $result->status);
        self::assertNotNull($result->domain);
        self::assertSame('example.com', $result->domain->domain);
        self::assertSame(DomainState::PENDING, $result->domain->state);
        self::assertSame('_sso-verification.example.com', $record);
        self::assertNotNull($value);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $value);
        self::assertStringNotContainsString($value, (string) json_encode($result->domain));
        self::assertCount(1, $claims);

        $claimed = $claims[0] ?? self::fail('No domain was reported claimed.');

        self::assertSame(User::class, $claimed->context->actingIdentityMorphClass);
        self::assertSame('admin-1', $claimed->context->actingIdentityId);
    }

    /**
     * A claim is exact and normalised: an internationalised name, in any case
     * and with a trailing dot, is stored as its lower-case ASCII form, and its
     * parent is a claim of its own.
     *
     * @return void
     */
    public function testAClaimIsNormalisedAndExact(): void
    {
        $domains = app(DomainService::class);

        self::assertSame('xn--bcher-kva.example.com', $this->claimed($domains, 'Bücher.Example.COM.')->domain);
        self::assertSame(DomainStatus::CLAIMED, $domains->claim(self::TENANT, $this->connectionId, 'example.com')->status);
    }

    /**
     * A claim of what could not be registered, of nothing, of a public mailbox
     * provider or a name under one, of a domain the connection already claimed,
     * or for a connection the tenant does not have is refused, and writes
     * nothing.
     *
     * @return void
     */
    public function testAClaimIsRefusedWithNothingWritten(): void
    {
        $domains = app(DomainService::class);

        self::assertSame(ViolationCode::INVALID_FORMAT, self::violationOf($domains->claim(self::TENANT, $this->connectionId, '192.0.2.1')));
        self::assertSame(ViolationCode::INVALID_FORMAT, self::violationOf($domains->claim(self::TENANT, $this->connectionId, '*.example.com')));
        self::assertSame(ViolationCode::REQUIRED, self::violationOf($domains->claim(self::TENANT, $this->connectionId, ' ')));
        self::assertSame(ViolationCode::NOT_ALLOWED, self::violationOf($domains->claim(self::TENANT, $this->connectionId, 'mail.gmail.com')));
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $domains->claim('tenant-2', $this->connectionId, 'example.com')->reason);
        self::assertSame([], $domains->list(self::TENANT, $this->connectionId));

        $this->claimed($domains, 'example.com');

        self::assertSame(ViolationCode::DUPLICATE, self::violationOf($domains->claim(self::TENANT, $this->connectionId, 'example.com')));
        self::assertCount(1, $domains->list(self::TENANT, $this->connectionId) ?? []);
    }

    /**
     * A caller who did not authenticate recently enough is refused a claim.
     *
     * @return void
     */
    public function testAClaimIsRefusedToAStaleCaller(): void
    {
        $this->instance(Freshness::class, FakeFreshness::stale());

        $result = app(DomainService::class)->claim(self::TENANT, $this->connectionId, 'example.com', $this->actor());

        self::assertSame(DomainStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
    }

    /**
     * A verification is refused while no record at the name is the token, and
     * concludes nothing when the lookup fails; once one record is the token the
     * domain is verified, and verifying it again is `unchanged` with nothing
     * looked up.
     *
     * @return void
     */
    public function testVerifyingLooksTheRecordUp(): void
    {
        $tenantId     = self::TENANT;
        $connectionId = $this->connectionId;
        $actor        = $this->actor();
        $domains      = app(DomainService::class);
        $claimed      = $this->claimed($domains, 'example.com');

        $this->dns->absent($claimed->recordName);

        self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $domains->verify($tenantId, $connectionId, 'example.com', $actor)->reason);

        $this->dns->found($claimed->recordName, 'not-the-token');

        self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $domains->verify($tenantId, $connectionId, 'example.com', $actor)->reason);

        $this->dns->failing($claimed->recordName);

        self::assertSame(FailureReason::DOMAIN_LOOKUP_FAILED, $domains->verify($tenantId, $connectionId, 'example.com', $actor)->reason);

        $this->dns->found($claimed->recordName, 'v=spf1 -all', $claimed->verificationToken());

        // @snippet-start domain-verify
        $result = $domains->verify($tenantId, $connectionId, 'example.com', $actor);
        // @snippet-end domain-verify
        self::assertSame(DomainStatus::VERIFIED, $result->status);
        self::assertTrue($result->domain?->isVerified());
        self::assertSame(DomainStatus::UNCHANGED, $domains->verify($tenantId, $connectionId, 'example.com', $actor)->status);

        $this->dns->assertLookedUp($claimed->recordName, 4);
    }

    /**
     * A domain the connection never claimed is `domain_not_found`; a claim left
     * past its expiry is `domain_claim_expired` with nothing looked up, and
     * claiming the domain again gives it a new token.
     *
     * @return void
     */
    public function testAnUnclaimedDomainOrAnExpiredClaimIsNotVerified(): void
    {
        $domains = app(DomainService::class);

        self::assertSame(FailureReason::DOMAIN_NOT_FOUND, $domains->verify(self::TENANT, $this->connectionId, 'example.com')->reason);

        $claimed = $this->claimed($domains, 'example.com');

        $this->dns->publishes($claimed);
        $this->clock->advance(604801);

        self::assertSame(FailureReason::DOMAIN_CLAIM_EXPIRED, $domains->verify(self::TENANT, $this->connectionId, 'example.com')->reason);
        self::assertNotSame($claimed->verificationToken(), $this->claimed($domains, 'example.com')->verificationToken());

        $this->dns->assertNothingLookedUp();
    }

    /**
     * A connection's domains are read one at a time and listed oldest first;
     * one verified for it is unavailable to another connection until it is
     * removed, which frees it at once; another tenant reads nothing.
     *
     * @return void
     */
    public function testDomainsAreReadListedAndRemoved(): void
    {
        $tenantId     = self::TENANT;
        $connectionId = $this->connectionId;
        $actor        = $this->actor();
        $domains      = app(DomainService::class);
        $other        = $this->makeOidcConnection(new FakeOpenIdProvider('https://other-op.example.test', clock: $this->clock));

        $this->dns->publishes($this->claimed($domains, 'example.com'));

        self::assertSame(DomainStatus::VERIFIED, $domains->verify($tenantId, $connectionId, 'example.com')->status);
        self::assertSame(FailureReason::DOMAIN_UNAVAILABLE, $domains->claim($tenantId, $other, 'example.com')->reason);

        $this->clock->advance(1);
        $this->claimed($domains, 'example.org');

        // @snippet-start domain-read-remove
        $domain  = $domains->get($tenantId, $connectionId, 'example.com');            // ?DomainSummary
        $listed  = $domains->list($tenantId, $connectionId);                          // ?list<DomainSummary>, oldest first
        $removed = $domains->remove($tenantId, $connectionId, 'example.com', $actor); // in any state
        // @snippet-end domain-read-remove
        self::assertTrue($domain?->isVerified());
        self::assertSame(['example.com', 'example.org'], self::namesOf($listed));
        self::assertSame(DomainStatus::REMOVED, $removed->status);
        self::assertNull($domains->get($tenantId, $connectionId, 'example.com'));
        self::assertSame(['example.org'], self::namesOf($domains->list($tenantId, $connectionId)));
        self::assertSame(DomainStatus::CLAIMED, $domains->claim($tenantId, $other, 'example.com')->status);
        self::assertNull($domains->get('tenant-2', $connectionId, 'example.org'));
        self::assertNull($domains->list('tenant-2', $connectionId));
    }

    /**
     * The application's resolver, bound by its service provider, answers every
     * lookup: a name that does not exist is no record, a failed answer, an
     * error status and a failed connection are failed lookups, and a record
     * whose character-strings join to the token verifies the domain. It asks
     * for the record name as absolute.
     *
     * @return void
     */
    public function testTheApplicationsResolverAnswersTheLookups(): void
    {
        app()->register(AppServiceProvider::class);

        self::assertInstanceOf(DohResolver::class, app(DnsResolver::class));
        self::assertSame(app(DnsResolver::class), app(DnsResolver::class));

        $domains = app(DomainService::class);
        $token   = $this->claimed($domains, 'example.com')->verificationToken();
        $split   = sprintf('"%s" "%s"', substr($token, 0, 32), substr($token, 32));

        Http::preventStrayRequests();
        Http::fake([DohResolver::ENDPOINT . '*' => Http::sequence()
            ->push(['Status' => 3])
            ->push(['Status' => 2])
            ->push(null, 503)
            ->pushFailedConnection()
            ->push(['Status' => 0, 'Answer' => [
                ['type' => 5, 'data' => 'elsewhere.example.net.'],
                ['type' => 16, 'data' => '"v=spf1 -all"'],
                ['type' => 16, 'data' => $split],
            ]]),
        ]);

        $reasons = array_map(fn (): ?FailureReason => $domains->verify(self::TENANT, $this->connectionId, 'example.com')->reason, range(1, 4));

        self::assertSame([FailureReason::DOMAIN_RECORD_NOT_FOUND, ...array_fill(0, 3, FailureReason::DOMAIN_LOOKUP_FAILED)], $reasons);
        self::assertSame(DomainStatus::VERIFIED, $domains->verify(self::TENANT, $this->connectionId, 'example.com')->status);

        Http::assertSequencesAreEmpty();
        Http::assertSent(static fn (Request $request): bool => $request->url() === DohResolver::ENDPOINT . '?name=_sso-verification.example.com.&type=TXT');
    }

    /**
     * The fake resolver answers the record name with the claim's token, so the
     * domain verifies, and records the one lookup.
     *
     * @return void
     */
    public function testTheFakeResolverAnswersWhatTheTestGivesIt(): void
    {
        $tenantId     = self::TENANT;
        $connectionId = $this->connectionId;

        // @snippet-start fake-dns-resolver
        $this->instance(DnsResolver::class, $dns = new FakeDnsResolver);

        $domains = app(DomainService::class);
        $claimed = $domains->claim($tenantId, $connectionId, 'example.com')->domain;

        self::assertNotNull($claimed);

        $dns->publishes($claimed); // or absent(), failing() or found() with records of your own

        self::assertSame(DomainStatus::VERIFIED, $domains->verify($tenantId, $connectionId, 'example.com')->status);

        $dns->assertLookedUp('_sso-verification.example.com', 1);
        // @snippet-end fake-dns-resolver
    }

    /**
     * The fake resolver fails the test loudly on a name it has no answer for.
     *
     * @return void
     */
    public function testTheFakeResolverFailsOnANameWithNoAnswer(): void
    {
        $domains = app(DomainService::class);

        $this->claimed($domains, 'example.com');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The fake DNS resolver has no answer for [_sso-verification.example.com].');

        $domains->verify(self::TENANT, $this->connectionId, 'example.com');
    }

    /**
     * The administrator as the package records who acted.
     *
     * @return \SineMacula\Laravel\Sso\Administration\ActingIdentity
     */
    private function actor(): ActingIdentity
    {
        return new ActingIdentity($this->user->getMorphClass(), (string) $this->user->getKey());
    }

    /**
     * Claim the domain for the connection, as the claim succeeded with.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainService  $domains
     * @param  string  $domain
     * @return \SineMacula\Laravel\Sso\Domains\DomainSummary
     */
    private function claimed(DomainService $domains, string $domain): DomainSummary
    {
        $result = $domains->claim(self::TENANT, $this->connectionId, $domain);

        self::assertSame(DomainStatus::CLAIMED, $result->status);

        return $result->domain ?? self::fail("The claim of {$domain} carried no domain.");
    }

    /**
     * The one violation an invalid result carries.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainResult  $result
     * @return \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function violationOf(DomainResult $result): ViolationCode
    {
        self::assertSame(DomainStatus::INVALID, $result->status);
        self::assertCount(1, $result->violations);

        return $result->violations[0]->code;
    }

    /**
     * The domain names of a listing, in its order.
     *
     * @param  ?list<\SineMacula\Laravel\Sso\Domains\DomainSummary>  $listed
     * @return list<string>
     */
    private static function namesOf(?array $listed): array
    {
        self::assertNotNull($listed);

        return array_map(static fn (DomainSummary $summary): string => $summary->domain, $listed);
    }
}
