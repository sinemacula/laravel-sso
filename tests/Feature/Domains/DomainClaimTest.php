<?php

declare(strict_types = 1);

namespace Tests\Feature\Domains;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainClaims;
use SineMacula\Laravel\Sso\Domains\DomainFinder;
use SineMacula\Laravel\Sso\Domains\DomainName;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\DomainSettings;
use SineMacula\Laravel\Sso\Domains\DomainSummary;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Models\Domain;
use Tests\Fixtures\Clients;

/**
 * Feature tests for claiming a domain.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainService::class)]
#[CoversClass(DomainFinder::class)]
#[CoversClass(DomainClaims::class)]
#[CoversClass(DomainName::class)]
#[CoversClass(DomainEvents::class)]
final class DomainClaimTest extends DomainServiceTestCase
{
    /**
     * A claim is pending with a fresh 32-byte hex token, expires in a week, and
     * is reported without it.
     *
     * @return void
     */
    public function testClaimsADomainPendingWithANewToken(): void
    {
        $result  = $this->claimDomain();
        $summary = self::summaryOf($result);

        self::assertSame(DomainStatus::CLAIMED, $result->status);
        self::assertTrue($result->isSucceeded());
        self::assertTrue($result->isChanged());
        self::assertSame('example.com', $summary->domain);
        self::assertSame(DomainState::PENDING, $summary->state);
        self::assertSame('_sso-verification.example.com', $summary->recordName);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $summary->verificationToken());
        self::assertSame('2026-11-01T09:30:00+00:00', $summary->claimedAt->toAtomString());
        self::assertSame('2026-11-08T09:30:00+00:00', $summary->pendingExpiresAt?->toAtomString());
        self::assertNull($summary->verifiedAt);
        self::assertSame($this->connection->id, $summary->connectionId);

        $row = Domain::query()->findOrFail($summary->id);

        self::assertSame($summary->verificationToken(), $row->verification_token);
        self::assertNull($row->verified_domain);

        $this->assertEventSequence([DomainClaimed::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(DomainClaimed::class, $event);
        self::assertSame($summary->id, $event->domainId);
        self::assertSame('example.com', $event->domain);
        self::assertSame('_sso-verification.example.com', $event->recordName);
        self::assertSame('2026-11-08T09:30:00+00:00', $event->pendingExpiresAt->toAtomString());
        self::assertSame($this->connection->id, $event->context->connectionId);
        self::assertSame(self::TENANT, $event->context->connectionTenantId);
        self::assertSame('oidc', $event->context->protocol);
        self::assertSame('App\Models\User', $event->context->actingIdentityMorphClass);
        self::assertSame('42', $event->context->actingIdentityId);
        self::assertStringNotContainsString($summary->verificationToken(), serialize($event));
        self::assertStringNotContainsString($summary->verificationToken(), (string) json_encode($result));
    }

    /**
     * The domain is stored trimmed, lower case, IDNA ASCII and without a
     * trailing dot.
     *
     * @return void
     */
    public function testNormalizesTheDomainGiven(): void
    {
        $summary = self::summaryOf($this->claimDomain(" Bücher.Example.COM.\n"));

        self::assertSame('xn--bcher-kva.example.com', $summary->domain);
        self::assertSame('_sso-verification.xn--bcher-kva.example.com', $summary->recordName);
    }

    /**
     * Each claim has its own token.
     *
     * @return void
     */
    public function testEachClaimHasItsOwnToken(): void
    {
        $first  = self::summaryOf($this->claimDomain('one.example.com'));
        $second = self::summaryOf($this->claimDomain('two.example.com'));

        self::assertNotSame($first->verificationToken(), $second->verificationToken());
    }

    /**
     * Rows of `[domain, code]`: what is not a registrable host name.
     *
     * @return iterable<string, array{string, \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode}>
     */
    public static function provideUnregistrableDomains(): iterable
    {
        yield 'nothing' => ['', ViolationCode::REQUIRED];
        yield 'whitespace' => ["  \t ", ViolationCode::REQUIRED];
        yield 'a single label' => ['localhost', ViolationCode::INVALID_FORMAT];
        yield 'an IPv4 address' => ['192.0.2.1', ViolationCode::INVALID_FORMAT];
        yield 'an IPv6 address' => ['[2001:db8::1]', ViolationCode::INVALID_FORMAT];
        yield 'a wildcard' => ['*.example.com', ViolationCode::INVALID_FORMAT];
        yield 'an underscore' => ['_dmarc.example.com', ViolationCode::INVALID_FORMAT];
        yield 'a URL' => ['https://example.com', ViolationCode::INVALID_FORMAT];
        yield 'an email address' => ['someone@example.com', ViolationCode::INVALID_FORMAT];
        yield 'an empty label' => ['example..com', ViolationCode::INVALID_FORMAT];
        yield 'a hyphen at the end of a label' => ['example-.com', ViolationCode::INVALID_FORMAT];
        yield 'a numeric top-level label' => ['example.123', ViolationCode::INVALID_FORMAT];
        yield 'a special-use top-level domain' => ['intranet.internal', ViolationCode::INVALID_FORMAT];
        yield 'a label of 64 characters' => [str_repeat('a', 64) . '.com', ViolationCode::INVALID_FORMAT];
        yield 'more than 253 characters' => [str_repeat('a.', 127) . 'com', ViolationCode::TOO_LONG];
    }

    /**
     * A domain that is not a registrable host name is invalid, with nothing
     * asked or written.
     *
     * @param  string  $domain
     * @param  \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode  $code
     * @return void
     */
    #[DataProvider('provideUnregistrableDomains')]
    public function testRefusesADomainThatIsNotARegistrableHostName(string $domain, ViolationCode $code): void
    {
        $result = $this->claimDomain($domain);

        self::assertTrue($result->isInvalid());
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame([['setting' => 'domain', 'code' => $code->value]], array_map(static fn ($violation): array => $violation->jsonSerialize(), $result->violations));
        self::assertSame([], $this->freshness->operations());
        self::assertSame(0, Domain::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A domain whose record name would exceed a DNS name's length is too long.
     *
     * @return void
     */
    public function testRefusesADomainTooLongForItsRecordName(): void
    {
        $domain = implode('.', array_fill(0, 4, str_repeat('a', 58))) . '.com';

        self::assertNotNull(DomainName::normalize($domain));

        $result = $this->claimDomain($domain);

        self::assertSame(ViolationCode::TOO_LONG, $result->violations[0]->code ?? null);
    }

    /**
     * A record name of exactly the longest DNS name is claimed; one character
     * more is too long.
     *
     * @return void
     */
    public function testClaimsADomainWhoseRecordNameIsExactlyTheLongest(): void
    {
        $longest = self::domainForRecordNameOf(DomainName::MAX_LENGTH);
        $claimed = $this->claimDomain($longest);

        self::assertSame(DomainStatus::CLAIMED, $claimed->status);
        self::assertSame(DomainName::MAX_LENGTH, strlen(self::summaryOf($claimed)->recordName));

        $tooLong = $this->claimDomain(self::domainForRecordNameOf(DomainName::MAX_LENGTH + 1));

        self::assertSame(ViolationCode::TOO_LONG, $tooLong->violations[0]->code ?? null);
        self::assertSame(1, Domain::query()->count());
    }

    /**
     * Rows of `[domain]`: public mailbox providers and their subdomains.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideMailboxDomains(): iterable
    {
        yield 'gmail.com' => ['gmail.com'];
        yield 'outlook.com in capitals' => ['OUTLOOK.COM'];
        yield 'a subdomain of yahoo.com' => ['mail.yahoo.com'];
        yield 'icloud.com with a trailing dot' => ['icloud.com.'];
    }

    /**
     * A public mailbox provider, or a subdomain of one, is never claimed.
     *
     * @param  string  $domain
     * @return void
     */
    #[DataProvider('provideMailboxDomains')]
    public function testRefusesAPublicMailboxProvider(string $domain): void
    {
        $result = $this->claimDomain($domain);

        self::assertTrue($result->isInvalid());
        self::assertSame(ViolationCode::NOT_ALLOWED, $result->violations[0]->code ?? null);
        self::assertSame(0, Domain::query()->count());
    }

    /**
     * A refused domain and its subdomains are refused; a domain above it is
     * not.
     *
     * @return void
     */
    public function testRefusesAConfiguredDomainAndItsSubdomains(): void
    {
        config()->set('sso.domains.refused', ['Shared.Example.org']);

        self::assertTrue($this->claimDomain('shared.example.org')->isInvalid());
        self::assertTrue($this->claimDomain('team.shared.example.org')->isInvalid());
        self::assertTrue($this->claimDomain('example.org')->isSucceeded());
        self::assertTrue($this->claimDomain('notshared.example.org')->isSucceeded());
    }

    /**
     * A subdomain of a verified domain is claimed on its own, pending, with its
     * own token.
     *
     * @return void
     */
    public function testClaimsAreExact(): void
    {
        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        $summary = self::summaryOf($this->claimDomain('eu.example.com'));

        self::assertSame('eu.example.com', $summary->domain);
        self::assertSame(DomainState::PENDING, $summary->state);
    }

    /**
     * Rows of `[state]`: each state a live claim can be in.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Sso\Domains\Enums\DomainState}>
     */
    public static function provideLiveStates(): iterable
    {
        yield 'pending' => [DomainState::PENDING];
        yield 'verified' => [DomainState::VERIFIED];
        yield 'lapsed' => [DomainState::LAPSED];
    }

    /**
     * A domain the connection holds a live claim of is a duplicate, whatever
     * its state.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\DomainState  $state
     * @return void
     */
    #[DataProvider('provideLiveStates')]
    public function testRefusesADomainTheConnectionClaimedAlready(DomainState $state): void
    {
        $claim = $this->makeDomain($this->connection, 'example.com', ['state' => $state]);

        $this->startRecordingEvents();

        $result = $this->claimDomain('Example.com');

        self::assertSame(ViolationCode::DUPLICATE, $result->violations[0]->code ?? null);
        self::assertSame($claim->verification_token, Domain::query()->findOrFail($claim->id)->verification_token);
        $this->assertNoEvents();
    }

    /**
     * An expired claim is claimed again on the same row with a new token and
     * times.
     *
     * @return void
     */
    public function testClaimsAnExpiredClaimAgainWithANewToken(): void
    {
        $first = self::summaryOf($this->claimDomain());

        $this->clock->advance(604800);
        $this->startRecordingEvents();

        $second = self::summaryOf($this->claimDomain());

        self::assertSame($first->id, $second->id);
        self::assertNotSame($first->verificationToken(), $second->verificationToken());
        self::assertSame('2026-11-08T09:30:00+00:00', $second->claimedAt->toAtomString());
        self::assertSame('2026-11-15T09:30:00+00:00', $second->pendingExpiresAt?->toAtomString());
        self::assertSame(1, Domain::query()->count());
        $this->assertEventSequence([DomainClaimed::class]);
    }

    /**
     * A domain verified for another tenant is `domain_unavailable`, naming
     * neither tenant nor connection.
     *
     * @return void
     */
    public function testRefusesADomainVerifiedForAnotherTenantWithoutNamingIt(): void
    {
        $other = $this->makeConnection(['tenant_id' => 'tenant-2']);

        $this->makeDomain($other, 'example.com', ['state' => DomainState::VERIFIED]);

        $this->startRecordingEvents();

        $result  = $this->claimDomain();
        $encoded = (string) json_encode($result);

        self::assertTrue($result->isRefused());
        self::assertSame(FailureReason::DOMAIN_UNAVAILABLE, $result->reason);
        self::assertNull($result->domain);
        self::assertStringNotContainsString('tenant-2', $encoded);
        self::assertStringNotContainsString($other->id, $encoded);
        self::assertSame(1, Domain::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A domain verified for another connection of the tenant is refused the
     * same way.
     *
     * @return void
     */
    public function testRefusesADomainVerifiedForAnotherConnectionOfTheTenant(): void
    {
        $this->makeDomain($this->makeConnection(), 'example.com', ['state' => DomainState::VERIFIED]);

        self::assertSame(FailureReason::DOMAIN_UNAVAILABLE, $this->claimDomain()->reason);
    }

    /**
     * A claim pending or lapsed elsewhere does not hold the domain.
     *
     * @return void
     */
    public function testAClaimPendingOrLapsedElsewhereDoesNotHoldTheDomain(): void
    {
        $this->makeDomain($this->makeConnection(['tenant_id' => 'tenant-2']), 'example.com');
        $this->makeDomain($this->makeConnection(['tenant_id' => 'tenant-3']), 'example.com', ['state' => DomainState::LAPSED]);

        self::assertSame(DomainStatus::CLAIMED, $this->claimDomain()->status);
    }

    /**
     * Foreign, unknown and case-variant tenants' connections are
     * `connection_not_found`.
     *
     * @return void
     */
    public function testAnotherTenantsConnectionIsNotFound(): void
    {
        $domains = $this->domains();

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $domains->claim('tenant-2', $this->connection->id, 'example.com', Clients::browser())->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $domains->claim('Tenant-1', $this->connection->id, 'example.com', Clients::browser())->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $domains->claim(self::TENANT, '01jbunknownconnection00000', 'example.com', Clients::browser())->reason);
        self::assertSame([], $this->freshness->operations());
    }

    /**
     * An empty tenant id is the application's mistake.
     *
     * @return void
     */
    public function testAnEmptyTenantIsAnInvalidArgument(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->domains()->claim('', $this->connection->id, 'example.com', Clients::browser());
    }

    /**
     * A stale caller is refused with `freshness_required`, with nothing written
     * or reported.
     *
     * @return void
     */
    public function testAStaleCallerIsRefusedWithNothingWritten(): void
    {
        config()->set('sso.freshness.max_age_seconds.domain_claim', 120);

        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->claimDomain();

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame([[FreshnessOperation::DOMAIN_CLAIM, 120]], $this->freshness->asked());
        self::assertSame(0, Domain::query()->count());
        $this->assertNoEvents();
    }

    /**
     * A fresh caller is asked about `sso.domain.claim` alone.
     *
     * @return void
     */
    public function testAFreshCallerIsAskedAboutTheClaimAlone(): void
    {
        $this->claimDomain();

        self::assertSame([[FreshnessOperation::DOMAIN_CLAIM, 300]], $this->freshness->asked());
    }

    /**
     * The configured record name and expiry apply to new claims only.
     *
     * @return void
     */
    public function testUsesTheConfiguredRecordNameAndExpiry(): void
    {
        config()->set('sso.domains.record_name', '_acme-sso');
        config()->set('sso.domains.pending_expiry_seconds', 3600);

        $claimed = self::summaryOf($this->claimDomain());

        config()->set('sso.domains.record_name', '_other');

        $read = $this->domains()->get(self::TENANT, $this->connection->id, 'example.com');

        self::assertSame('_acme-sso.example.com', $claimed->recordName);
        self::assertSame('2026-11-01T10:30:00+00:00', $claimed->pendingExpiresAt?->toAtomString());
        self::assertSame('_acme-sso.example.com', $read?->recordName);
    }

    /**
     * A malformed setting fails closed before anything is asked or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedRecordNameFailsClosed(): void
    {
        config()->set('sso.domains.record_name', 'Not A Label');

        try {
            $this->domains()->claim(self::TENANT, $this->connection->id, 'example.com', Clients::browser());
            self::fail('A malformed record name was used.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('sso.domains.record_name', $exception->getMessage());
        }

        self::assertSame(0, Domain::query()->count());
    }

    /**
     * `get()` answers the claim however the domain is written, else `null`.
     *
     * @return void
     */
    public function testGetsAClaimOrNothing(): void
    {
        $claimed = self::summaryOf($this->claimDomain());
        $domains = $this->domains();

        self::assertSame($claimed->id, $domains->get(self::TENANT, $this->connection->id, 'EXAMPLE.com.')?->id);
        self::assertNull($domains->get('tenant-2', $this->connection->id, 'example.com'));
        self::assertNull($domains->get(self::TENANT, $this->connection->id, 'example.org'));
        self::assertNull($domains->get(self::TENANT, $this->connection->id, 'not a domain'));
    }

    /**
     * `list()` answers the connection's claims oldest first, or `null` for an
     * unknown connection.
     *
     * @return void
     */
    public function testListsTheConnectionsClaimsOldestFirst(): void
    {
        $first = self::summaryOf($this->claimDomain('b.example.com'));

        $this->clock->advance(1);

        $second = self::summaryOf($this->claimDomain('a.example.com'));

        $this->makeDomain($this->makeConnection(), 'other.example.com');

        $listed = $this->domains()->list(self::TENANT, $this->connection->id);

        self::assertSame([$first->id, $second->id], array_map(static fn (DomainSummary $summary): string => $summary->id, $listed ?? []));
        self::assertNull($this->domains()->list('tenant-2', $this->connection->id));
        self::assertSame([], $this->domains()->list(self::TENANT, $this->makeConnection()->id));
    }

    /**
     * Every read is made on the write connection.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $this->makeDomain($this->makeConnection(['tenant_id' => 'tenant-2']), 'taken.example.com', ['state' => DomainState::VERIFIED]);

        $domains = $this->domains();
        $id      = $this->connection->id;

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $claimed     = $domains->claim(self::TENANT, $id, 'example.com', Clients::browser());
            $duplicate   = $domains->claim(self::TENANT, $id, 'example.com', Clients::browser());
            $unavailable = $domains->claim(self::TENANT, $id, 'taken.example.com', Clients::browser());
            $read        = $domains->get(self::TENANT, $id, 'example.com');
            $listed      = $domains->list(self::TENANT, $id);
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame(DomainStatus::CLAIMED, $claimed->status);
        self::assertTrue($duplicate->isInvalid());
        self::assertSame(FailureReason::DOMAIN_UNAVAILABLE, $unavailable->reason);
        self::assertNotNull($read);
        self::assertCount(1, $listed ?? []);
    }

    /**
     * A registrable domain whose default record name is exactly the given
     * length.
     *
     * @param  int  $length
     * @return string
     */
    private static function domainForRecordNameOf(int $length): string
    {
        $domainLength = $length - strlen(DomainSettings::DEFAULT_RECORD_NAME) - 1;

        return implode('.', array_fill(0, 3, str_repeat('a', 63))) . '.' . str_repeat('b', $domainLength - 196) . '.com';
    }
}
