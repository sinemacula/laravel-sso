<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AssertionMapper;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for SAML's linking evidence.
 *
 * What the fake provider cannot write is judged on the assertion the validator
 * would read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssertionValidator::class)]
#[CoversClass(AssertionMapper::class)]
final class LinkingAssertionValidatorTest extends TestCase
{
    use UsesConnections;

    /** @var string The request the responses answer. */
    private const string REQUEST_ID = '_request-1';

    /** @var string The attribute the connection names. */
    private const string ATTRIBUTE = 'urn:oid:0.9.2342.19200300.100.1.3';

    /** @var string The attribute's format. */
    private const string URI = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';

    /** @var string Another format. */
    private const string BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /** @var string What an attribute with no format is in. */
    private const string UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';

    /** @var string The address asserted. */
    private const string EMAIL = 'Person@Example.COM';

    /** @var string The organisation attribute. */
    private const string ORGANIZATION = 'organization-id';

    /** @var string The organisation's value. */
    private const string VALUE = 'the-organisation';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock, configure the endpoints and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.features.domain_linking', true);

        $this->usePackageTables();
    }

    /**
     * The attribute named, once, with one value in exactly the format, is the
     * linking email, kept as asserted.
     *
     * @return void
     */
    public function testTheAttributeNamedIsTheLinkingEmail(): void
    {
        $claims = $this->validated(self::linking(), [self::ATTRIBUTE => [self::EMAIL]], self::URI);

        self::assertSame(['email' => self::EMAIL, 'source' => 'saml_attribute', 'organization' => null], $claims['linking']);
        self::assertSame([self::ATTRIBUTE => [self::EMAIL]], $claims['attributes']);
    }

    /**
     * Rows of `[what changes on the settings, the attributes, their format]`:
     * each a signed response that gives no linking email.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, list<string>>, 2: ?string}>
     */
    public static function provideResponsesWithNoLinkingEmail(): iterable
    {
        $good = [self::ATTRIBUTE => [self::EMAIL]];

        yield 'linking off' => [['linking_enabled' => false], $good, self::URI];
        yield 'no acknowledgement' => [['linking_acknowledged_at' => null], $good, self::URI];
        yield 'no attribute named' => [['linking_saml_attribute' => null], $good, self::URI];
        yield 'no format named' => [['linking_saml_attribute_format' => null], $good, self::URI];
        yield 'two values' => [[], [self::ATTRIBUTE => [self::EMAIL, 'other@example.com']], self::URI];
        yield 'a value that is no address' => [[], [self::ATTRIBUTE => ['not-an-address']], self::URI];
        yield 'a different format' => [[], $good, self::BASIC];
        yield 'no format, not named unspecified' => [[], $good, null];
        yield 'another attribute' => [[], ['mail' => [self::EMAIL]], self::URI];
        yield 'the name in another case' => [[], [strtoupper(self::ATTRIBUTE) => [self::EMAIL]], self::URI];
        yield 'no attributes, the NameID alone' => [[], [], self::URI];
    }

    /**
     * Each such response is verified, and carries no linking email.
     *
     * @param  array<string, mixed>  $change
     * @param  array<string, list<string>>  $attributes
     * @param  ?string  $format
     * @return void
     */
    #[DataProvider('provideResponsesWithNoLinkingEmail')]
    public function testAResponseWithNoLinkingEmail(array $change, array $attributes, ?string $format): void
    {
        self::assertNull($this->validated($change + self::linking(), $attributes, $format)['linking']);
    }

    /**
     * Rows of `[the attribute's values]`: what a provider may send that the
     * library may also refuse.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideEmptyValues(): iterable
    {
        yield 'an empty value' => [['']];
        yield 'no value' => [[]];
    }

    /**
     * An attribute with an empty value or none gives no linking email, whether
     * or not the response is otherwise accepted.
     *
     * @param  list<string>  $values
     * @return void
     */
    #[DataProvider('provideEmptyValues')]
    public function testAnEmptyAttributeGivesNone(array $values): void
    {
        self::assertNull($this->completion(self::linking(), [self::ATTRIBUTE => $values], self::URI)->claims?->linkingEmail);
    }

    /**
     * An email-format `NameID` alone gives none, for all that it is an address.
     *
     * @return void
     */
    public function testAnEmailFormatNameIdIsNoFallback(): void
    {
        $settings = ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL, 'name_id_format' => 'email'];

        $claims = $this->validated(['settings' => $settings] + self::linking(), [], self::URI, [
            'name_id'        => self::EMAIL,
            'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        ]);

        self::assertNull($claims['linking']);
    }

    /**
     * An attribute with no `NameFormat` is `unspecified`, so naming that format
     * finds it, as a provider that sends none needs.
     *
     * @return void
     */
    public function testAnAttributeWithNoFormatIsUnspecified(): void
    {
        $linking = ['linking_saml_attribute_format' => self::UNSPECIFIED] + self::linking();

        self::assertSame(self::EMAIL, $this->validated($linking, [self::ATTRIBUTE => [self::EMAIL]], null)['linking']['email'] ?? null);
        self::assertSame(self::EMAIL, $this->validated($linking, [self::ATTRIBUTE => [self::EMAIL]], self::UNSPECIFIED)['linking']['email'] ?? null);
        self::assertNull($this->validated($linking, [self::ATTRIBUTE => [self::EMAIL]], self::URI)['linking']);
    }

    /**
     * The organisation comes from the attribute named as the claim, in the same
     * format, and the mapped attributes do not supply it.
     *
     * @return void
     */
    public function testTheOrganizationComesFromItsAttribute(): void
    {
        $linking = ['linking_organization_claim' => self::ORGANIZATION] + self::linking();

        $named = [self::ATTRIBUTE => [self::EMAIL], self::ORGANIZATION => [self::VALUE]];

        self::assertSame(self::VALUE, $this->validated($linking, $named, self::URI)['linking']['organization'] ?? null);
        self::assertSame(
            ['email' => self::EMAIL, 'source' => 'saml_attribute', 'organization' => null],
            $this->validated($linking, [self::ATTRIBUTE => [self::EMAIL], 'another' => [self::VALUE]], self::URI)['linking'],
        );
    }

    /**
     * Rows of `[the attributes of an assertion, what the linking email is]`,
     * including what the fake identity provider cannot write.
     *
     * @return iterable<string, array{0: list<array{0: string, 1: ?string, 2: ?string, 3: list<?string>}>, 1: ?string}>
     */
    public static function provideAssertions(): iterable
    {
        yield 'exactly right' => [[[self::ATTRIBUTE, self::URI, null, [self::EMAIL]]], self::EMAIL];
        yield 'with a friendly name too' => [[[self::ATTRIBUTE, self::URI, 'mail', [self::EMAIL]]], self::EMAIL];
        yield 'a friendly name alone' => [[['another', self::URI, self::ATTRIBUTE, [self::EMAIL]]], null];
        yield 'named twice' => [[[self::ATTRIBUTE, self::URI, null, [self::EMAIL]], [self::ATTRIBUTE, self::URI, null, [self::EMAIL]]], null];
        yield 'named twice, in another format' => [[[self::ATTRIBUTE, self::URI, null, [self::EMAIL]], [self::ATTRIBUTE, self::BASIC, null, [self::EMAIL]]], null];
        yield 'a value that is not text' => [[[self::ATTRIBUTE, self::URI, null, [null]]], null];
        yield 'one value, and one that is not text' => [[[self::ATTRIBUTE, self::URI, null, [self::EMAIL, null]]], null];
        yield 'no value' => [[[self::ATTRIBUTE, self::URI, null, []]], null];
        yield 'an empty value' => [[[self::ATTRIBUTE, self::URI, null, ['']]], null];
        yield 'two @' => [[[self::ATTRIBUTE, self::URI, null, ['a@b@example.com']]], null];
        yield 'too long an address' => [[[self::ATTRIBUTE, self::URI, null, [str_repeat('a', LinkingEmail::MAX_EMAIL_LENGTH) . '@example.com']]], null];
    }

    /**
     * What the validator reads of an assertion's attributes.
     *
     * @param  list<array{0: string, 1: ?string, 2: ?string, 3: list<?string>}>  $attributes
     * @param  ?string  $email
     * @return void
     */
    #[DataProvider('provideAssertions')]
    public function testWhatAnAssertionGives(array $attributes, ?string $email): void
    {
        self::assertSame($email, AssertionValidator::linkingEmail(self::assertion($attributes), self::settings())?->email);
    }

    /**
     * An encrypted attribute might be the attribute named a second time, so no
     * linking email stands beside one.
     *
     * @return void
     */
    public function testAnEncryptedAttributeGivesNone(): void
    {
        $attributes = [new SamlAttribute(self::ATTRIBUTE, self::URI, null, [self::EMAIL])];
        $issuedAt   = CarbonImmutable::parse('2026-11-01T09:30:00Z');
        $assertion  = new SamlAssertion('_a', new NameId('https://idp.example.test'), $issuedAt, attributes: $attributes, facts: ['encrypted_attributes' => 1]);

        self::assertNull(AssertionValidator::linkingEmail($assertion, self::settings()));
    }

    /**
     * Rows of `[the organisation attribute's values, the organisation]`.
     *
     * @return iterable<string, array{0: list<?string>, 1: ?string}>
     */
    public static function provideOrganizations(): iterable
    {
        yield 'one value' => [[self::VALUE], self::VALUE];
        yield 'the longest value' => [[str_repeat('v', 255)], str_repeat('v', 255)];
        yield 'one byte over the longest' => [[str_repeat('v', 256)], null];
        yield 'two values' => [[self::VALUE, self::VALUE], null];
        yield 'an empty value' => [[''], null];
        yield 'a value that is not text' => [[null], null];
    }

    /**
     * The organisation is held to the same rule, and is only ever a string a
     * result can hold, and the email stands without it.
     *
     * @param  list<?string>  $values
     * @param  ?string  $organization
     * @return void
     */
    #[DataProvider('provideOrganizations')]
    public function testTheOrganizationsExactness(array $values, ?string $organization): void
    {
        $email = AssertionValidator::linkingEmail(
            self::assertion([[self::ATTRIBUTE, self::URI, null, [self::EMAIL]], [self::ORGANIZATION, self::URI, null, $values]]),
            ['organization_claim' => self::ORGANIZATION] + self::settings(),
        );

        self::assertSame(self::EMAIL, $email?->email);
        self::assertSame($organization, $email->organization);
    }

    /**
     * The organisation in another format is not the one named, and neither is
     * one held by a friendly name.
     *
     * @return void
     */
    public function testTheOrganizationInAnotherFormatOrByFriendlyNameIsNotIt(): void
    {
        $settings = ['organization_claim' => self::ORGANIZATION] + self::settings();
        $email    = [self::ATTRIBUTE, self::URI, null, [self::EMAIL]];

        self::assertNull(AssertionValidator::linkingEmail(self::assertion([$email, [self::ORGANIZATION, self::BASIC, null, [self::VALUE]]]), $settings)?->organization);
        self::assertNull(AssertionValidator::linkingEmail(self::assertion([$email, ['another', self::URI, self::ORGANIZATION, [self::VALUE]]]), $settings)?->organization);
    }

    /**
     * With the feature off no linking email is built, whatever the connection.
     *
     * @return void
     */
    public function testNoLinkingEmailWhileTheFeatureIsOff(): void
    {
        config()->set('sso.features.domain_linking', false);

        self::assertNull(AssertionValidator::linkingEmail(self::assertion([[self::ATTRIBUTE, self::URI, null, [self::EMAIL]]]), self::settings()));
    }

    /**
     * Rows of `[what changes on the settings]`: linking not on as it must be.
     *
     * @return iterable<string, array{0: array<string, bool|int|string|null>}>
     */
    public static function provideOffSettings(): iterable
    {
        yield 'off' => [['enabled' => false]];
        yield 'not acknowledged' => [['acknowledged' => false]];
        yield 'no attribute' => [['saml_attribute' => null]];
        yield 'no format' => [['saml_attribute_format' => null]];
        yield 'enabled only in a manner of speaking' => [['enabled' => 1]];
        yield 'acknowledged only in a manner of speaking' => [['acknowledged' => 1]];
    }

    /**
     * No linking email is built unless linking is on, acknowledged and named.
     *
     * @param  array<string, bool|int|string|null>  $change
     * @return void
     */
    #[DataProvider('provideOffSettings')]
    public function testNoLinkingEmailUnlessItIsOnAndNamed(array $change): void
    {
        self::assertNull(AssertionValidator::linkingEmail(self::assertion([[self::ATTRIBUTE, self::URI, null, [self::EMAIL]]]), $change + self::settings()));
    }

    /**
     * Rows of `[the setting left out]`: what a connection must state, not what
     * its absence might be taken to mean.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnstatedSettings(): iterable
    {
        yield 'enabled' => ['enabled'];
        yield 'acknowledged' => ['acknowledged'];
    }

    /**
     * A connection that does not state a setting has not turned it on.
     *
     * @param  string  $setting
     * @return void
     */
    #[DataProvider('provideUnstatedSettings')]
    public function testASettingNotStatedIsOff(string $setting): void
    {
        $settings = self::settings();

        unset($settings[$setting]);

        self::assertNull(AssertionValidator::linkingEmail(self::assertion([[self::ATTRIBUTE, self::URI, null, [self::EMAIL]]]), $settings));
    }

    /**
     * Validate a signed response with the attributes and format given and
     * answer what it verified.
     *
     * @param  array<string, mixed>  $linking
     * @param  array<string, list<string>>  $attributes
     * @param  ?string  $format
     * @param  array<string, mixed>  $options
     * @return array{linking: ?array<string, mixed>, attributes: array<string, mixed>}
     */
    private function validated(array $linking, array $attributes, ?string $format, array $options = []): array
    {
        $completion = $this->completion($linking, $attributes, $format, $options);

        self::assertNull($completion->reason);
        self::assertNotNull($completion->claims);

        return ['linking' => $completion->claims->linkingEmail?->toArray(), 'attributes' => $completion->claims->attributes];
    }

    /**
     * Validate a signed response with the attributes and format, through a
     * connection with those linking columns.
     *
     * @param  array<string, mixed>  $linking
     * @param  array<string, list<string>>  $attributes
     * @param  ?string  $format
     * @param  array<string, mixed>  $options
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function completion(array $linking, array $attributes, ?string $format, array $options = []): Completion
    {
        $connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
            ...$linking,
        ]);

        $this->trust($connection);

        $endpoints = app(EndpointResolver::class)->endpoints($connection);
        $response  = self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())
            ->with(['attributes' => $attributes, 'attribute_name_format' => $format, 'authn_statements' => [self::statement($this->clock->now())], ...$options])
            ->inResponseTo(self::REQUEST_ID);
        $reference = RequestReference::fromString('Vq8tVv3w0kLmNoPqRsTuVwXyZ0123456');
        $consumed  = new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, $this->clock->now()->subMinute(), samlRequestId: self::REQUEST_ID);

        return app(AssertionValidator::class)->validate($connection, Saml2Options::of($connection), $response->completionRequest('relay'), $consumed);
    }

    /**
     * Trust the identity provider's certificate on the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     *
     * @throws \LogicException
     */
    private function trust(Connection $connection): void
    {
        $certificate = self::idp()->certificate();
        $details     = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => is_array($details) ? $details['key'] : '',
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();
    }

    /**
     * The linking columns of a connection with everything named.
     *
     * @return array<string, mixed>
     */
    private static function linking(): array
    {
        return [
            'linking_enabled'               => true,
            'linking_issuer_class'          => 'single_organization',
            'linking_saml_attribute'        => self::ATTRIBUTE,
            'linking_saml_attribute_format' => self::URI,
            'linking_acknowledged_at'       => CarbonImmutable::parse('2026-11-01T09:00:00Z'),
        ];
    }

    /**
     * The settings a connection with everything named answers.
     *
     * @return array<string, bool|int|string|null>
     */
    private static function settings(): array
    {
        return [
            'enabled'               => true,
            'issuer_class'          => 'single_organization',
            'organization_claim'    => null,
            'organization_value'    => null,
            'saml_attribute'        => self::ATTRIBUTE,
            'saml_attribute_format' => self::URI,
            'acknowledged'          => true,
            'version'               => 0,
        ];
    }

    /**
     * An assertion with the attributes.
     *
     * @param  list<array{0: string, 1: ?string, 2: ?string, 3: list<?string>}>  $attributes
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function assertion(array $attributes): SamlAssertion
    {
        return new SamlAssertion(
            '_assertion',
            new NameId('https://idp.example.test'),
            CarbonImmutable::parse('2026-11-01T09:30:00Z'),
            attributes: array_map(static fn (array $attribute): SamlAttribute => new SamlAttribute(...$attribute), $attributes),
        );
    }

    /**
     * An authentication statement a minute old.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return array<string, mixed>
     */
    private static function statement(CarbonImmutable $now): array
    {
        return [
            'instant'                 => $now->subMinute(),
            'session_index'           => '_session-1',
            'session_not_on_or_after' => $now->addHours(8),
            'class'                   => FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT,
        ];
    }

    /**
     * The trusted identity provider, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
