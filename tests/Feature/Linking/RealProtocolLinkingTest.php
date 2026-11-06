<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\Stages\DomainReservation;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Linking\DomainLinkEligibility;
use SineMacula\Laravel\Sso\Linking\ReservationActivation;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Fixtures\Clients;

/**
 * Linking by a verified domain through the real drivers (SSO-8.8, SSO-7.7): a
 * signed ID token and a signed assertion, through the public callback and the
 * assertion consumer service, to a reservation, and through `admit()` to an
 * active link of verified domain provenance. The other tests of the machine
 * verify through a driver that answers what the test sets, and the protocols'
 * own tests stop at the claims; this is what joins them: the result's issuer,
 * its email's source and its organisation are what the protocol's rules accept,
 * at completion and again as they are restored at redemption.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainLinkEligibility::class)]
#[CoversClass(ReservationActivation::class)]
#[CoversClass(DomainReservation::class)]
final class RealProtocolLinkingTest extends LinkingTestCase
{
    /** @var string Google's issuer, shared by many organisations, told apart by `hd`. */
    private const string GOOGLE = 'https://accounts.google.com';

    /** @var string The organisation's value. */
    private const string ORGANIZATION = 'acme.example';

    /** @var string The SAML attribute the email is read from. */
    private const string EMAIL_ATTRIBUTE = 'email';

    /** @var string The SAML attribute the organisation is read from. */
    private const string ORGANIZATION_ATTRIBUTE = 'organization-id';

    /** @var string The format of the SAML attributes. */
    private const string BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, made once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /**
     * Set the endpoints and SAML.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.features.saml2', true);
    }

    /**
     * A shared issuer's ID token whose `hd` is exactly the organisation's
     * reserves, with what it asserted as the binding, and activates at
     * redemption from the result the code restores.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASharedIssuersIdTokenReservesAndActivates(): void
    {
        [$provider, $start] = $this->openIdFlow();

        $completion = $this->openIdCallback($provider, $start, self::ORGANIZATION);

        self::assertTrue($completion->isCompleted(), (string) $completion->reason?->value);

        $reserved = Link::query()->sole();

        self::assertSame(LinkState::RESERVED, $reserved->state);
        self::assertSame(self::ORGANIZATION, $reserved->reservation_organization);
        self::assertSame((new LinkSubject(self::GOOGLE, FakeOpenIdProvider::SUBJECT))->key(), $reserved->subject_key);
        self::assertSame(self::EMAIL, $this->matcher->queries[0]->email());
        self::assertSame('example.com', $this->matcher->queries[0]->domain);

        $this->assertActivates($completion, $start, $reserved);
    }

    /**
     * Rows of `[the ID token's `hd`]`, none of which is the organisation's.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideWrongOrganizations(): iterable
    {
        yield 'absent' => [null];
        yield 'another organisation' => ['other.example'];
        yield 'another case' => ['ACME.example'];
    }

    /**
     * Any other `hd` reserves nothing, though the email's domain is verified:
     * another of the issuer's organisations could assert that address.
     *
     * @param  ?string  $organization
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideWrongOrganizations')]
    public function testASharedIssuersIdTokenOfAnotherOrganizationReservesNothing(?string $organization): void
    {
        [$provider, $start] = $this->openIdFlow();

        $completion = $this->openIdCallback($provider, $start, $organization);

        self::assertSame(FailureReason::UNLINKED, $completion->reason);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Rows of `[the linking policy, the assertion's attributes]` that link.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, list<string>>, 2: ?string}>
     */
    public static function provideSamlLinks(): iterable
    {
        yield 'one organisation' => [
            ['linking_issuer_class' => 'single_organization'],
            [self::EMAIL_ATTRIBUTE => [self::EMAIL]],
            null,
        ];
        yield 'a shared issuer' => [
            ['linking_issuer_class' => 'shared', 'linking_organization_claim' => self::ORGANIZATION_ATTRIBUTE, 'linking_organization_value' => self::ORGANIZATION],
            [self::EMAIL_ATTRIBUTE => [self::EMAIL], self::ORGANIZATION_ATTRIBUTE => [self::ORGANIZATION]],
            self::ORGANIZATION,
        ];
    }

    /**
     * An assertion's named attribute, with the administrator's acknowledgement,
     * reserves and activates; a shared issuer's organisation comes from the
     * attribute the connection names.
     *
     * @param  array<string, mixed>  $policy
     * @param  array<string, list<string>>  $attributes
     * @param  ?string  $organization
     * @return void
     */
    #[DataProvider('provideSamlLinks')]
    public function testASamlAssertionReservesAndActivates(array $policy, array $attributes, ?string $organization): void
    {
        $this->connection = $this->samlConnection($policy);

        $start      = $this->start();
        $completion = $this->assertion($start, $attributes);

        self::assertTrue($completion->isCompleted(), (string) $completion->reason?->value);

        $reserved = Link::query()->sole();

        self::assertSame(LinkState::RESERVED, $reserved->state);
        self::assertSame($organization, $reserved->reservation_organization);
        self::assertSame(self::EMAIL, $this->matcher->queries[0]->email());

        $this->assertActivates($completion, $start, $reserved);
    }

    /**
     * Rows of `[the linking policy, the assertion's attributes]` that do not:
     * each is one step from a row above.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, list<string>>}>
     */
    public static function provideSamlRefusals(): iterable
    {
        yield 'no acknowledgement' => [
            ['linking_issuer_class' => 'single_organization', 'linking_acknowledged_at' => null],
            [self::EMAIL_ATTRIBUTE => [self::EMAIL]],
        ];
        yield 'the email in another attribute' => [
            ['linking_issuer_class' => 'single_organization'],
            ['mail' => [self::EMAIL]],
        ];
        yield 'a shared issuer, another organisation' => [
            ['linking_issuer_class' => 'shared', 'linking_organization_claim' => self::ORGANIZATION_ATTRIBUTE, 'linking_organization_value' => self::ORGANIZATION],
            [self::EMAIL_ATTRIBUTE => [self::EMAIL], self::ORGANIZATION_ATTRIBUTE => ['other.example']],
        ];
        yield 'a shared issuer, no organisation' => [
            ['linking_issuer_class' => 'shared', 'linking_organization_claim' => self::ORGANIZATION_ATTRIBUTE, 'linking_organization_value' => self::ORGANIZATION],
            [self::EMAIL_ATTRIBUTE => [self::EMAIL]],
        ];
    }

    /**
     * Without the acknowledgement, the named attribute or the organisation
     * nothing reserves.
     *
     * @param  array<string, mixed>  $policy
     * @param  array<string, list<string>>  $attributes
     * @return void
     */
    #[DataProvider('provideSamlRefusals')]
    public function testASamlAssertionThatDoesNotQualifyReservesNothing(array $policy, array $attributes): void
    {
        $this->connection = $this->samlConnection($policy);

        $completion = $this->assertion($this->start(), $attributes);

        self::assertSame(FailureReason::UNLINKED, $completion->reason);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Assert the redemption activates the reservation: the same row, active, of
     * verified domain provenance, with its binding cleared, resolved to the
     * person.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionResult  $completion
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  \SineMacula\Laravel\Sso\Models\Link  $reserved
     * @return void
     */
    private function assertActivates(CompletionResult $completion, StartResult $start, Link $reserved): void
    {
        $answer = $this->admit($completion, $start);
        $active = Link::query()->sole();

        self::assertTrue($answer->isRedeemed(), (string) $answer->reason?->value);
        self::assertSame($this->person->id, $answer->linkedIdentity?->id);
        self::assertSame($reserved->id, $active->id);
        self::assertSame(LinkState::ACTIVE, $active->state);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $active->provenance);
        self::assertNull($active->reservation_id);
        self::assertNull($active->reservation_organization);
    }

    /**
     * An OpenID Connect connection at Google's issuer, classified shared under
     * `hd`, holding the verified claim, with a flow started through it.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider, 1: \SineMacula\Laravel\Sso\Flows\StartResult}
     */
    private function openIdFlow(): array
    {
        $fetcher  = new FakeFetcher;
        $provider = (new FakeOpenIdProvider(self::GOOGLE, self::key(), $this->clock))->serve($fetcher);
        $jwks     = (string) json_encode(['keys' => [self::key()->jwk()]]);

        $this->app?->instance(Fetcher::class, $fetcher);

        $this->connection = $this->withClaim($this->makeConnection([
            'enabled'  => true,
            'jwks'     => ProviderKeySet::read($jwks, AlgorithmAllowList::of(['RS256']), 65536, 50)?->toStored(),
            'secrets'  => app(ConnectionSecrets::class)->apply(null, ['client_secret' => new Secret(FakeOpenIdProvider::CLIENT_SECRET)]),
            'settings' => [
                'issuer'                 => $provider->issuer,
                'authorization_endpoint' => $provider->endpoint('authorization'),
                'token_endpoint'         => $provider->endpoint('token'),
                'jwks_uri'               => $provider->endpoint('jwks'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
            ],
            'linking_enabled'            => true,
            'linking_issuer_class'       => 'shared',
            'linking_organization_claim' => 'hd',
            'linking_organization_value' => self::ORGANIZATION,
        ]));

        return [$provider, $this->start()];
    }

    /**
     * Answer the callback with an ID token asserting the verified email and the
     * organisation.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider  $provider
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  ?string  $organization
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     *
     * @throws \Random\RandomException
     */
    private function openIdCallback(FakeOpenIdProvider $provider, StartResult $start, ?string $organization): CompletionResult
    {
        $grant = $provider->authorize((string) $start->navigation?->url(), static function (FakeIdToken $token) use ($organization): FakeIdToken {
            $token = $token->with('email', self::EMAIL)->with('email_verified', true);

            return $organization === null ? $token : $token->with('hd', $organization);
        });

        return app(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $this->connection->id, new CompletionRequest('GET', $grant->query(), []), Clients::browser());
    }

    /**
     * A SAML connection trusting the identity provider's certificate, reading
     * the email from its named attribute, acknowledged unless the policy says
     * otherwise, and holding the verified claim.
     *
     * @param  array<string, mixed>  $policy
     * @return \SineMacula\Laravel\Sso\Models\Connection
     *
     * @throws \LogicException
     */
    private function samlConnection(array $policy): Connection
    {
        $connection = $this->makeConnection([
            'protocol'                      => 'saml2',
            'enabled'                       => true,
            'settings'                      => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
            'attribute_mapping'             => [],
            'linking_enabled'               => true,
            'linking_saml_attribute'        => self::EMAIL_ATTRIBUTE,
            'linking_saml_attribute_format' => self::BASIC,
            'linking_acknowledged_at'       => CarbonImmutable::parse('2026-11-01T00:00:00Z'),
            ...$policy,
        ]);

        $certificate = self::idp()->certificate();
        $details     = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'state'         => null,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'private_key'   => null,
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();

        return $this->withClaim($connection);
    }

    /**
     * The connection, holding the verified claim of `example.com`, which the
     * set-up's connection gives up.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function withClaim(Connection $connection): Connection
    {
        $this->domain->delete();

        $now          = $this->clock->now();
        $this->domain = $this->makeDomain($connection, 'example.com', [
            'state'                    => DomainState::VERIFIED,
            'verified_domain'          => 'example.com',
            'verified_at'              => $now->subDay(),
            'verification_generation'  => 1,
            'last_successful_check_at' => $now,
        ]);

        return $connection;
    }

    /**
     * Post the assertion consumer service a signed response to the flow's
     * request, with the attributes.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult  $start
     * @param  array<string, list<string>>  $attributes
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function assertion(StartResult $start, array $attributes): CompletionResult
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);
        $request   = AuthorizationRequest::query()->where('reference', $start->reference?->value)->sole();
        $response  = self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())
            ->with(['attributes' => $attributes, 'attribute_name_format' => self::BASIC])
            ->inResponseTo($request->saml_request_id);

        parse_str((string) parse_url((string) $start->navigation?->url(), PHP_URL_QUERY), $query);

        /** @var array{RelayState?: string} $query */
        $posted = new CompletionRequest('POST', '', ['SAMLResponse' => $response->encoded(), 'RelayState' => $query['RelayState'] ?? '']);

        return app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connection->id, $posted, Clients::browser());
    }

    /**
     * The OpenID provider's key.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa('rsa-1');
    }

    /**
     * The SAML identity provider.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
