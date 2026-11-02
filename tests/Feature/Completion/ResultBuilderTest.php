<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\ResultBuilder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Results\AssertedEmail;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for building a completion's verified result (SSO-8.1, SSO-2.10,
 * SSO-3.3): every part from the claims, the connection and the consumed
 * request, the subject exactly as received, the attributes through the
 * connection's mapping and its caps, and whether the email's domain is
 * verified: routing for this connection, of another connection, pending,
 * lapsed, at its lapse and either side, and malformed; and the asserted email,
 * passed through from the claims, never derived from the mapped attributes, and
 * kept through the handoff store.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResultBuilder::class)]
final class ResultBuilderTest extends TestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Bq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The S256 challenge of the client's verifier. */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the response arrived for. */
    private Connection $connection;

    /**
     * Bind a fixed clock, and create the tables and a connection that maps the
     * email, the given name, the groups and a custom attribute.
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

        $this->connection = $this->makeConnection([
            'tenant_id'         => 'tenant-7',
            'protocol'          => 'oidc',
            'attribute_mapping' => ['email' => 'mail', 'given_name' => 'given', 'groups' => 'memberOf', 'department' => 'dept'],
        ]);
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
     * The result holds the claims' issuer, subject exactly as received, format,
     * authentication context and linking email; the connection's id, tenant and
     * protocol; the request's application, purpose and reference; and the
     * mapped attributes, and nothing else.
     *
     * @return void
     */
    public function testTheResultIsBuiltFromTheClaimsTheConnectionAndTheRequest(): void
    {
        $claims = new VerifiedClaims(
            'https://idp.example.com',
            "  Subject\u{00A0}1 ",
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            ['mail' => 'person@example.com', 'given' => 'Ada', 'memberOf' => 'staff', 'dept' => ['Research', 'Ops'], 'ignored' => 'x'],
            new AuthenticationContext(CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd'], 'urn:example:class', 'session-index-1', null),
            new LinkingEmail('person@example.com', LinkingEmailSource::SAML_ATTRIBUTE, 'example.com'),
        );

        $result = $this->build($claims, Purpose::LINK);

        self::assertSame([
            'issuer'                 => 'https://idp.example.com',
            'subject'                => "  Subject\u{00A0}1 ",
            'name_id_format'         => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'connection_id'          => $this->connection->id,
            'tenant_id'              => 'tenant-7',
            'protocol'               => 'oidc',
            'application'            => 'native',
            'purpose'                => 'link',
            'request_reference'      => self::REFERENCE,
            'attributes'             => ['email' => 'person@example.com', 'given_name' => 'Ada', 'groups' => ['staff'], 'department' => ['Research', 'Ops']],
            'email_domain_verified'  => false,
            'authentication_context' => [
                'authenticated_at'          => '2026-11-01T09:29:00.000000Z',
                'methods'                   => ['pwd'],
                'context_class'             => 'urn:example:class',
                'provider_session_id'       => 'session-index-1',
                'provider_session_deadline' => null,
            ],
            'linking_email' => ['email' => 'person@example.com', 'source' => 'saml_attribute', 'organization' => 'example.com'],
        ], $result->toArray());

        self::assertSame($claims->authenticationContext, $result->authenticationContext);
        self::assertSame($claims->linkingEmail, $result->linkingEmail);
    }

    /**
     * The attributes are cut to the mapping's caps: each list to its most
     * values, and each value to its longest length.
     *
     * @return void
     */
    public function testTheAttributesAreCutToTheMappingsCaps(): void
    {
        config()->set('sso.mapping.max_values', 1);
        config()->set('sso.mapping.max_value_length', 64);

        $result = $this->build(self::claims(['mail' => 'person@example.com', 'given' => str_repeat('a', 70), 'memberOf' => ['staff', 'admins']]));

        self::assertSame(['email' => 'person@example.com', 'given_name' => str_repeat('a', 64), 'groups' => ['staff']], $result->attributes);
    }

    /**
     * Emails whose domain routes for the connection.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideVerifiedEmails(): iterable
    {
        yield 'an email' => ['person@example.com'];
        yield 'a one-letter local part' => ['p@example.com'];
        yield 'a domain to normalise' => ['Person@EXAMPLE.com.'];
        yield 'the last @' => ['a@b@example.com'];
        yield 'the first of a list' => [['person@example.com', 'person@other.example']];
    }

    /**
     * The email's domain is verified when it routes for this connection: a
     * verified claim not past its lapse, the first string of a listed email, an
     * email with a domain that normalises, and the domain after the last `@`.
     *
     * @param  mixed  $email
     * @return void
     */
    #[DataProvider('provideVerifiedEmails')]
    public function testAnEmailWhoseDomainRoutesForTheConnectionIsVerified(mixed $email): void
    {
        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        self::assertTrue($this->build(self::claims(['mail' => $email]))->emailDomainVerified);
    }

    /**
     * Emails that are not one, or whose domain does not normalise.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedEmails(): iterable
    {
        yield 'no @' => ['example.com'];
        yield 'no local part' => ['@example.com'];
        yield 'no domain' => ['person@'];
        yield 'a single label' => ['person@localhost'];
        yield 'a space in the domain' => ['person@exa mple.com'];
        yield 'not a string' => [42];
        yield 'no strings' => [[1, 2]];
    }

    /**
     * An email that is not one, or whose domain does not normalise, is never
     * verified, whatever is claimed.
     *
     * @param  mixed  $email
     * @return void
     */
    #[DataProvider('provideMalformedEmails')]
    public function testAMalformedEmailIsNotVerified(mixed $email): void
    {
        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        self::assertFalse($this->build(self::claims(['mail' => $email]))->emailDomainVerified);
    }

    /**
     * A result whose claims carry no email has no verified email.
     *
     * @return void
     */
    public function testAResultWithNoEmailIsNotVerified(): void
    {
        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        self::assertFalse($this->build(self::claims(['given' => 'Ada']))->emailDomainVerified);
    }

    /**
     * A domain verified for another connection, pending for this one, or
     * lapsed, does not verify the email.
     *
     * @return void
     */
    public function testADomainThatDoesNotRouteForTheConnectionIsNotVerified(): void
    {
        $other = $this->makeConnection(['tenant_id' => 'tenant-8']);

        $this->makeDomain($other, 'example.com', ['state' => DomainState::VERIFIED]);
        $this->makeDomain($this->connection, 'example.com');
        $this->makeDomain($this->connection, 'lapsed.example.org', ['state' => DomainState::LAPSED, 'lapsed_at' => $this->clock->now()]);

        self::assertFalse($this->build(self::claims(['mail' => 'person@example.com']))->emailDomainVerified);
        self::assertFalse($this->build(self::claims(['mail' => 'person@lapsed.example.org']))->emailDomainVerified);
        self::assertFalse($this->build(self::claims(['mail' => 'person@unclaimed.example.org']))->emailDomainVerified);
    }

    /**
     * Seconds from now to the lapse, and whether the domain still routes.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideLapseBoundaries(): iterable
    {
        yield 'one second before its lapse' => [1, true];
        yield 'at its lapse' => [0, false];
        yield 'one second after its lapse' => [-1, false];
    }

    /**
     * A verified domain whose record has gone routes until its lapse: one
     * second before it, but not at it or after it.
     *
     * @param  int  $offset
     * @param  bool  $verified
     * @return void
     */
    #[DataProvider('provideLapseBoundaries')]
    public function testAVerifiedDomainRoutesUntilItsLapse(int $offset, bool $verified): void
    {
        $this->makeDomain($this->connection, 'example.com', [
            'state'                => DomainState::VERIFIED,
            'linking_suspended_at' => $this->clock->now()->subDay(),
            'lapses_at'            => $this->clock->now()->addSeconds($offset),
        ]);

        self::assertSame($verified, $this->build(self::claims(['mail' => 'person@example.com']))->emailDomainVerified);
    }

    /**
     * The asserted email is the claims', the same value, kept apart from the
     * mapped attributes even when the mapped email is another, and stored last.
     *
     * @return void
     */
    public function testTheAssertedEmailIsPassedThroughFromTheClaims(): void
    {
        $asserted = new AssertedEmail('asserted@example.com', false, LinkingEmailSource::USERINFO);
        $claims   = new VerifiedClaims('https://op.example.com', 'sub-1', null, ['mail' => 'mapped@example.com'], new AuthenticationContext, null, $asserted);

        $result = $this->build($claims);

        self::assertSame($asserted, $result->assertedEmail);
        self::assertSame('mapped@example.com', $result->attributes['email']);
        self::assertNull($result->linkingEmail);
        self::assertSame(['email' => 'asserted@example.com', 'verified' => false, 'source' => 'userinfo'], $result->toArray()['asserted_email']);
    }

    /**
     * Claims with no asserted email give a result with none, whatever the
     * mapped attributes hold: it is never derived from them.
     *
     * @return void
     */
    public function testTheAssertedEmailIsNeverDerivedFromTheMappedAttributes(): void
    {
        $result = $this->build(self::claims(['mail' => 'mapped@example.com', 'email_verified' => true]));

        self::assertSame('mapped@example.com', $result->attributes['email']);
        self::assertNull($result->assertedEmail);
        self::assertNull($result->linkingEmail);
        self::assertArrayNotHasKey('asserted_email', $result->toArray());
    }

    /**
     * A result stored by the handoff store, encrypted, reads back with its
     * asserted email exactly as it was built, each thing `email_verified` may
     * be.
     *
     * @return void
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    public function testTheHandoffStoreKeepsTheAssertedEmail(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        foreach ([true, false, null] as $verified) {

            $asserted = new AssertedEmail(' Asserted+Tag@Example.COM ', $verified, LinkingEmailSource::ID_TOKEN);
            $claims   = new VerifiedClaims('https://op.example.com', 'sub-1', null, ['given' => 'Ada'], new AuthenticationContext, null, $asserted);
            $result   = $this->build($claims);

            $app->make(DatabaseHandoffStore::class)->issue(new HandoffGrant($result, S256Challenge::fromString(self::CHALLENGE), $this->clock->now()->addMinute()));

            $row = StoredCode::query()->sole();

            self::assertStringNotContainsString('Asserted+Tag', $row->result);

            $restored = self::readBack($row, $app->make(SecretEncrypter::class));

            self::assertSame($result->toArray(), $restored->toArray());
            self::assertSame(['email' => ' Asserted+Tag@Example.COM ', 'verified' => $verified, 'source' => 'id_token'], $restored->assertedEmail?->toArray());

            StoredCode::query()->delete();
        }
    }

    /**
     * The verified result a stored code carries, as a redemption reads it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \UnexpectedValueException
     */
    private static function readBack(StoredCode $code, SecretEncrypter $encrypter): VerifiedResult
    {
        /** @var array<string, mixed> $stored */
        $stored = json_decode($encrypter->decrypt($code->result), true);

        return VerifiedResult::restore($stored);
    }

    /**
     * Build the result of the claims for a request through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function build(VerifiedClaims $claims, Purpose $purpose = Purpose::SIGN_IN): VerifiedResult
    {
        $consumed = new ConsumedRequest($purpose, 'native', RequestReference::fromString(self::REFERENCE), $this->clock->now()->subMinute());

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ResultBuilder::class)->build($claims, $this->connection, $consumed);
    }

    /**
     * Claims with the attributes given.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    private static function claims(array $attributes): VerifiedClaims
    {
        return new VerifiedClaims('https://op.example.com', 'sub-1', null, $attributes, new AuthenticationContext);
    }
}
