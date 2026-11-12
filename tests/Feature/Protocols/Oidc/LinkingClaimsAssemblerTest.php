<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClaimsAssembler;
use SineMacula\Laravel\Sso\Protocols\Oidc\EmailPairing;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for OpenID Connect's linking evidence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClaimsAssembler::class)]
#[CoversClass(EmailPairing::class)]
final class LinkingClaimsAssemblerTest extends TestCase
{
    /** @var string The connection's issuer. */
    private const string ISSUER = 'https://op.example.test';

    /** @var string The connection's UserInfo endpoint. */
    private const string ENDPOINT = 'https://op.example.test/userinfo';

    /** @var string The ID token's subject. */
    private const string SUBJECT = 'the-subject';

    /** @var string The address asserted. */
    private const string EMAIL = 'Person+Tag@Example.COM';

    /** @var string The organisation claim named. */
    private const string CLAIM = 'hd';

    /** @var string The organisation's value. */
    private const string VALUE = 'acme.example';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher UserInfo is requested through. */
    private FakeFetcher $fetcher;

    /**
     * Bind the fake fetcher.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.domain_linking', true);
    }

    /**
     * With linking off no linking email is built, whatever the evidence, and
     * the pair is carried as asserted.
     *
     * @return void
     */
    public function testNoLinkingEmailWhileLinkingIsOff(): void
    {
        $claims = $this->assembled(['email' => self::EMAIL, 'email_verified' => true, self::CLAIM => self::VALUE], null, false)->claims;

        self::assertNull($claims?->linkingEmail);
        self::assertSame(['email' => self::EMAIL, 'verified' => true, 'source' => 'id_token'], $claims?->assertedEmail?->toArray());
    }

    /**
     * With the feature off no linking email is built, whatever the connection.
     *
     * @return void
     */
    public function testNoLinkingEmailWhileTheFeatureIsOff(): void
    {
        config()->set('sso.features.domain_linking', false);

        $claims = $this->assembled(['email' => self::EMAIL, 'email_verified' => true], null)->claims;

        self::assertNull($claims?->linkingEmail);
        self::assertNotNull($claims?->assertedEmail);
    }

    /**
     * A connection that does not state its linking settings has not turned
     * linking on.
     *
     * @return void
     */
    public function testNoLinkingEmailFromAConnectionThatStatesNoLinkingSettings(): void
    {
        $connection = new ExampleConnection('oidc', ['fetch_userinfo' => false, 'userinfo_endpoint' => self::ENDPOINT], linking: []);

        $claims = $this->assembledFor($connection, ['email' => self::EMAIL, 'email_verified' => true])->claims;

        self::assertNull($claims?->linkingEmail);
        self::assertNotNull($claims?->assertedEmail);
    }

    /**
     * Rows of `[ID token's claims, UserInfo's members, its stored form]`,
     * UserInfo fetched when its members are given.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: ?array<string, mixed>, 2: ?array{email: string, source: string, organization: ?string}}>
     */
    public static function provideEvidence(): iterable
    {
        $verified = ['email' => self::EMAIL, 'email_verified' => true];
        $org      = [self::CLAIM => self::VALUE];

        yield 'the ID token' => [$verified + $org, null, ['email' => self::EMAIL, 'source' => 'id_token', 'organization' => self::VALUE]];
        yield 'UserInfo' => [[], $verified + $org, ['email' => self::EMAIL, 'source' => 'userinfo', 'organization' => self::VALUE]];
        yield 'the ID token, UserInfo fetched' => [$verified + $org, ['name' => 'A Name'], ['email' => self::EMAIL, 'source' => 'id_token', 'organization' => self::VALUE]];
        yield 'the ID token, with the organisation only in UserInfo' => [$verified, $org, ['email' => self::EMAIL, 'source' => 'id_token', 'organization' => null]];
        yield 'UserInfo, with the organisation only in the ID token' => [$org, $verified, ['email' => self::EMAIL, 'source' => 'userinfo', 'organization' => null]];
        yield 'the ID token, with another organisation in UserInfo' => [$verified + $org, [self::CLAIM => 'other'], self::stored('id_token', self::VALUE)];
        yield 'UserInfo, with another organisation in the ID token' => [[self::CLAIM => 'other'], $verified + $org, self::stored('userinfo', self::VALUE)];
        yield 'no organisation at all' => [$verified, null, ['email' => self::EMAIL, 'source' => 'id_token', 'organization' => null]];
        yield 'the organisation is never the email domain' => [
            ['email' => 'person@acme.example', 'email_verified' => true],
            null,
            ['email' => 'person@acme.example', 'source' => 'id_token', 'organization' => null],
        ];
        yield 'the string true' => [['email' => self::EMAIL, 'email_verified' => 'true'], null, null];
        yield 'the number one' => [['email' => self::EMAIL, 'email_verified' => 1], null, null];
        yield 'false' => [['email' => self::EMAIL, 'email_verified' => false], null, null];
        yield 'absent' => [['email' => self::EMAIL], null, null];
        yield 'the email from the ID token, verified only by UserInfo' => [['email' => self::EMAIL], ['email' => self::EMAIL, 'email_verified' => true], null];
        yield 'the email from UserInfo, verified only by the ID token' => [['email_verified' => true], ['email' => self::EMAIL], null];
        yield 'no address' => [['email' => 'not-an-address', 'email_verified' => true], null, null];
    }

    /**
     * A linking email needs its own source's `email_verified` exactly true, and
     * takes the organisation from that same source.
     *
     * @param  array<string, mixed>  $idToken
     * @param  ?array<string, mixed>  $userInfo
     * @param  ?array{email: string, source: string, organization: ?string}  $expected
     * @return void
     */
    #[DataProvider('provideEvidence')]
    public function testTheEvidence(array $idToken, ?array $userInfo, ?array $expected): void
    {
        self::assertSame($expected, $this->assembled($idToken, $userInfo)->claims?->linkingEmail?->toArray());
    }

    /**
     * Rows of `[the organisation claim's value, what is kept]`: only a string
     * of 1 to 255 bytes.
     *
     * @return iterable<string, array{0: mixed, 1: ?string}>
     */
    public static function provideOrganizationValues(): iterable
    {
        yield 'a string' => [self::VALUE, self::VALUE];
        yield 'one byte' => ['a', 'a'];
        yield 'one under the most' => [str_repeat('v', 254), str_repeat('v', 254)];
        yield 'the most' => [str_repeat('v', 255), str_repeat('v', 255)];
        yield 'one over the most' => [str_repeat('v', 256), null];
        yield 'empty' => ['', null];
        yield 'a number' => [7, null];
        yield 'true' => [true, null];
        yield 'null' => [null, null];
        yield 'a list' => [[self::VALUE], null];
        yield 'an object' => [['value' => self::VALUE], null];
    }

    /**
     * The organisation is set only when it is a string a result can hold; the
     * email links without it.
     *
     * @param  mixed  $value
     * @param  ?string  $kept
     * @return void
     */
    #[DataProvider('provideOrganizationValues')]
    public function testTheOrganizationIsAStringOrNothing(mixed $value, ?string $kept): void
    {
        $email = $this->assembled(['email' => self::EMAIL, 'email_verified' => true, self::CLAIM => $value], null)->claims?->linkingEmail;

        self::assertSame(self::EMAIL, $email?->email);
        self::assertSame(LinkingEmailSource::ID_TOKEN, $email->source);
        self::assertSame($kept, $email->organization);
    }

    /**
     * With no claim named, no organisation is read, even with such a claim, and
     * only the claim named counts.
     *
     * @return void
     */
    public function testOnlyTheClaimNamedIsRead(): void
    {
        $present = ['email' => self::EMAIL, 'email_verified' => true, self::CLAIM => self::VALUE];

        self::assertNull($this->assembled($present, null, true, null)->claims?->linkingEmail?->organization);
        self::assertNull($this->assembled($present, null, true, 'org')->claims?->linkingEmail?->organization);
        self::assertNull($this->assembled($present, null, true, 'HD')->claims?->linkingEmail?->organization);
    }

    /**
     * A UserInfo response of another subject is refused, with no fallback to
     * the ID token's evidence.
     *
     * @return void
     */
    public function testUserInfoOfAnotherSubjectIsRefused(): void
    {
        $idToken    = ['email' => self::EMAIL, 'email_verified' => true, self::CLAIM => self::VALUE];
        $completion = $this->assembled($idToken, ['sub' => 'another-subject', 'email' => self::EMAIL, 'email_verified' => true]);

        self::assertSame(FailureReason::USERINFO_INVALID, $completion->reason);
        self::assertNull($completion->claims);
    }

    /**
     * What the pairing reads for an organisation, directly: a claim named by a
     * string, in the claims it is given.
     *
     * @return void
     */
    public function testThePairingReadsTheOrganizationOfTheClaimsItIsGiven(): void
    {
        self::assertSame(self::VALUE, EmailPairing::organization([self::CLAIM => self::VALUE], self::CLAIM));
        self::assertNull(EmailPairing::organization([self::CLAIM => self::VALUE], null));
        self::assertNull(EmailPairing::organization([self::CLAIM => self::VALUE], 7));
        self::assertNull(EmailPairing::organization([], self::CLAIM));
    }

    /**
     * The stored form of the address, from the source, under the organisation.
     *
     * @param  string  $source
     * @param  ?string  $organization
     * @return array{email: string, source: string, organization: ?string}
     */
    private static function stored(string $source, ?string $organization): array
    {
        return ['email' => self::EMAIL, 'source' => $source, 'organization' => $organization];
    }

    /**
     * Assemble the claims of the ID token and UserInfo response given, for a
     * connection with linking as given.
     *
     * @param  array<string, mixed>  $idToken
     * @param  ?array<string, mixed>  $userInfo
     * @param  bool  $linking
     * @param  ?string  $claim
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function assembled(array $idToken, ?array $userInfo, bool $linking = true, ?string $claim = self::CLAIM): Completion
    {
        if ($userInfo !== null) {
            $this->fetcher->respond(self::ENDPOINT, FakeTokenEndpoint::json(200, ['sub' => self::SUBJECT, ...$userInfo]));
        }

        $connection = (new Connection)->forceFill([
            'id'                         => '01jbexampleconnection00000',
            'tenant_id'                  => 'tenant-1',
            'protocol'                   => 'oidc',
            'settings'                   => ['fetch_userinfo' => $userInfo !== null, 'userinfo_endpoint' => self::ENDPOINT],
            'linking_enabled'            => $linking,
            'linking_issuer_class'       => 'shared',
            'linking_organization_claim' => $claim,
            'linking_organization_value' => self::VALUE,
        ]);

        return $this->assembledFor($connection, $idToken);
    }

    /**
     * Assemble the claims of an ID token with those given, for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  array<string, mixed>  $idToken
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function assembledFor(SsoConnection $connection, array $idToken): Completion
    {
        $token    = new ValidatedIdToken(self::ISSUER, self::SUBJECT, ['iss' => self::ISSUER, 'sub' => self::SUBJECT, 'aud' => 'the-client', ...$idToken]);
        $consumed = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString('Cq8tVv3w0kLmNoPqRsTuVwXyZ0123456'), CarbonImmutable::parse('2026-11-01T09:28:00Z'));

        $tokens = new TokenResponse('header.payload.signature', 'the-access-token');

        return app(ClaimsAssembler::class)->assemble($connection, OidcOptions::of($connection), $token, $tokens, $consumed);
    }
}
