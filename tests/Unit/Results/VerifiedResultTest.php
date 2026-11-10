<?php

declare(strict_types = 1);

namespace Tests\Unit\Results;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Results\AssertedEmail;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\StoredValues;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\DumpsValues;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Unit tests for the verified result: what it holds, its stored form, which
 * serialisation and JSON write, read back with every part checked again, the
 * bounds on each part, and the asserted email: stored and read back whole, and
 * shown by the result's and the claims' JSON and dumps only without its email.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifiedResult::class)]
#[CoversClass(StoredValues::class)]
#[CoversClass(VerifiedClaims::class)]
#[CoversClass(AssertedEmail::class)]
final class VerifiedResultTest extends TestCase
{
    use DumpsValues;

    /** @var string The email the provider asserted, exactly as received. */
    private const string ASSERTED_EMAIL = ' Asserted+Tag@Example.COM ';

    /** @var string A part of that email no class or property name shares. */
    private const string ASSERTED_PART = 'Asserted+Tag';

    /**
     * The stored form holds every part, under its snake_case name, and nothing
     * else; the subject exactly as received.
     *
     * @return void
     */
    public function testTheStoredFormHoldsEveryPart(): void
    {
        $expected = [
            'issuer'                 => 'https://idp.example.com',
            'subject'                => 'Subject 1 ',
            'name_id_format'         => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'connection_id'          => '01jbexampleconnection00000',
            'tenant_id'              => 'tenant-1',
            'protocol'               => 'saml2',
            'application'            => 'web',
            'purpose'                => 'link',
            'request_reference'      => ExampleResults::REFERENCE,
            'attributes'             => ['email' => 'person@example.com', 'groups' => ['staff', 'admins']],
            'email_domain_verified'  => true,
            'authentication_context' => [
                'authenticated_at'          => '2026-11-01T10:00:00.123456Z',
                'methods'                   => ['pwd', 'otp'],
                'context_class'             => 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
                'provider_session_id'       => 'session-index-1',
                'provider_session_deadline' => '2026-11-01T18:00:00.000000Z',
            ],
            'linking_email' => ['email' => 'person@example.com', 'source' => 'saml_attribute', 'organization' => 'example.com'],
        ];

        $result = ExampleResults::full(Purpose::LINK);

        self::assertSame($expected, $result->toArray());
        self::assertSame($expected, $result->jsonSerialize());
        self::assertSame($expected, $result->__serialize());
        self::assertNull(ExampleResults::bare()->toArray()['linking_email']);
    }

    /**
     * What is stored reads back as the same result, through `restore()` and
     * through `unserialize()`.
     *
     * @return void
     */
    public function testReadsBackWhatItStored(): void
    {
        foreach ([ExampleResults::full(Purpose::REAUTHENTICATE), ExampleResults::bare()] as $result) {

            $restored = VerifiedResult::restore($result->toArray());

            self::assertSame($result->toArray(), $restored->toArray());
            self::assertSame($result->purpose, $restored->purpose);
            self::assertTrue($result->requestReference->is($restored->requestReference));

            $unserialised = unserialize(serialize($result));
            $json         = json_decode((string) json_encode($result), true);

            self::assertInstanceOf(VerifiedResult::class, $unserialised);
            self::assertIsArray($json);
            self::assertSame($result->toArray(), $unserialised->toArray());
            self::assertSame($result->toArray(), VerifiedResult::restore($json)->toArray());
        }
    }

    /**
     * Rows of `[change]`: stored forms the package never wrote.
     *
     * @return iterable<string, array{0: \Closure(array<string, mixed>): array<string, mixed>}>
     */
    public static function provideCorruptForms(): iterable
    {
        yield 'no issuer' => [static fn (array $stored): array => array_diff_key($stored, ['issuer' => true])];
        yield 'an empty subject' => [static fn (array $stored): array => ['subject' => ''] + $stored];
        yield 'a numeric subject' => [static fn (array $stored): array => ['subject' => 1] + $stored];
        yield 'an unknown purpose' => [static fn (array $stored): array => ['purpose' => 'admin'] + $stored];
        yield 'a malformed reference' => [static fn (array $stored): array => ['request_reference' => 'ref-1'] + $stored];
        yield 'attributes that are not a map' => [static fn (array $stored): array => ['attributes' => 'email'] + $stored];
        yield 'an attribute that is a number' => [static fn (array $stored): array => ['attributes' => ['age' => 30]] + $stored];
        yield 'a verified flag that is a string' => [static fn (array $stored): array => ['email_domain_verified' => '1'] + $stored];
        yield 'no verified flag' => [static fn (array $stored): array => array_diff_key($stored, ['email_domain_verified' => true])];
        yield 'a context that is not a map' => [static fn (array $stored): array => ['authentication_context' => null] + $stored];
        $context = static fn (array $change): \Closure => static fn (array $stored): array => ['authentication_context' => $change + $stored['authentication_context']] + $stored;

        yield 'an instant in another form' => [$context(['authenticated_at' => '2026-11-01 10:00:00'])];
        yield 'an instant that overflows' => [$context(['authenticated_at' => '2026-13-01T10:00:00.000000Z'])];
        yield 'methods that are not a list' => [$context(['methods' => ['a' => 'pwd']])];
        yield 'a linking email that is a string' => [static fn (array $stored): array => ['linking_email' => 'person@example.com'] + $stored];
        yield 'a linking email of no source' => [static fn (array $stored): array => ['linking_email' => ['email' => 'person@example.com', 'source' => 'header']] + $stored];
        yield 'a linking email with no @' => [static fn (array $stored): array => ['linking_email' => ['email' => 'person', 'source' => 'id_token']] + $stored];
        yield 'an asserted email that is a string' => [static fn (array $stored): array => ['asserted_email' => 'person@example.com'] + $stored];
        yield 'an asserted email with no email' => [static fn (array $stored): array => ['asserted_email' => ['verified' => true, 'source' => 'id_token']] + $stored];
        yield 'an asserted email of no source' => [static fn (array $stored): array => ['asserted_email' => ['email' => 'person@example.com', 'source' => 'header']] + $stored];
        yield 'an asserted email with a string flag' => [
            static fn (array $stored): array => ['asserted_email' => ['email' => 'person@example.com', 'verified' => 'true', 'source' => 'id_token']] + $stored,
        ];
    }

    /**
     * A stored form the package never wrote fails as corrupt storage.
     *
     * @param  \Closure(array<string, mixed>): array<string, mixed>  $change
     * @return void
     */
    #[DataProvider('provideCorruptForms')]
    public function testRefusesAFormItNeverWrote(\Closure $change): void
    {
        $this->expectExceptionObject(new \UnexpectedValueException('A stored verified result is not one the package wrote.'));

        VerifiedResult::restore($change(ExampleResults::full()->toArray()));
    }

    /**
     * A corrupt serialisation fails as corrupt storage too.
     *
     * @return void
     */
    public function testRefusesACorruptSerialization(): void
    {
        $serialised = unserialize(str_replace('s:5:"saml2"', 's:5:"saml3"', serialize(ExampleResults::full())));

        self::assertInstanceOf(VerifiedResult::class, $serialised);
        self::assertSame('saml3', $serialised->protocol);

        $this->expectException(\UnexpectedValueException::class);

        unserialize(str_replace('s:7:"purpose";s:7:"sign_in"', 's:7:"purpose";s:7:"sign_on"', serialize(ExampleResults::full())));
    }

    /**
     * Each text part is bounded: the issuer and subject at 1024 bytes, the
     * NameID format at 255, the ids at 255.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBoundsEachPart(): void
    {
        self::assertSame(1024, VerifiedResult::MAX_ISSUER_LENGTH);
        self::assertSame(1024, VerifiedResult::MAX_SUBJECT_LENGTH);
        self::assertSame(255, VerifiedResult::MAX_NAME_ID_FORMAT_LENGTH);
        self::assertSame(255, VerifiedResult::MAX_ID_LENGTH);

        $at = self::aResult(issuer: str_repeat('i', 1024), subject: str_repeat('s', 1024), format: str_repeat('f', 255), id: str_repeat('c', 255));

        self::assertSame(1024, strlen($at->subject));

        $failures = [];

        $cases = [
            'issuer'              => ['issuer' => str_repeat('i', 1025)],
            'empty issuer'        => ['issuer' => ''],
            'subject'             => ['subject' => str_repeat('s', 1025)],
            'empty subject'       => ['subject' => ''],
            'NameID format'       => ['format' => str_repeat('f', 256)],
            'empty NameID format' => ['format' => ''],
            'connection id'       => ['id' => str_repeat('c', 256)],
            'empty connection id' => ['id' => ''],
        ];

        foreach ($cases as $case => $arguments) {
            try {
                self::aResult(...$arguments);
                $failures[$case] = 'accepted';
            } catch (\InvalidArgumentException $exception) {
                $failures[$case] = $exception->getMessage();
            }
        }

        self::assertSame([
            'issuer'              => 'A verified result\'s issuer is 1 to 1024 bytes.',
            'empty issuer'        => 'A verified result\'s issuer is 1 to 1024 bytes.',
            'subject'             => 'A verified result\'s subject is 1 to 1024 bytes.',
            'empty subject'       => 'A verified result\'s subject is 1 to 1024 bytes.',
            'NameID format'       => 'A verified result\'s NameID format is 1 to 255 bytes.',
            'empty NameID format' => 'A verified result\'s NameID format is 1 to 255 bytes.',
            'connection id'       => 'A verified result\'s connection id is 1 to 255 bytes.',
            'empty connection id' => 'A verified result\'s connection id is 1 to 255 bytes.',
        ], $failures);
    }

    /**
     * The tenant, protocol and application are bounded as the connection id is.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBoundsTheTenantProtocolAndApplication(): void
    {
        $messages = [];

        $valid = [
            'issuer'                => 'https://idp.example.com',
            'subject'               => 's',
            'nameIdFormat'          => null,
            'connectionId'          => 'c',
            'tenantId'              => 't',
            'protocol'              => 'oidc',
            'application'           => 'web',
            'purpose'               => Purpose::SIGN_IN,
            'requestReference'      => RequestReference::generate(),
            'attributes'            => [],
            'emailDomainVerified'   => false,
            'authenticationContext' => new AuthenticationContext,
        ];

        foreach (['tenantId', 'protocol', 'application'] as $argument) {
            try {
                new VerifiedResult(...array_replace($valid, [$argument => str_repeat('x', 256)])); // @phpstan-ignore argument.type
            } catch (\InvalidArgumentException $exception) {
                $messages[] = $exception->getMessage();
            }
        }

        self::assertSame([
            'A verified result\'s tenant id is 1 to 255 bytes.',
            'A verified result\'s protocol is 1 to 255 bytes.',
            'A verified result\'s application is 1 to 255 bytes.',
        ], $messages);
    }

    /**
     * Rows of `[attributes]`: attributes that are not strings or lists of
     * strings under non-empty names.
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function provideMalformedAttributes(): iterable
    {
        yield 'a numbered attribute' => [[0 => 'value']];
        yield 'an empty name' => [['' => 'value']];
        yield 'a number' => [['age' => 30]];
        yield 'a map' => [['groups' => ['a' => 'staff']]];
        yield 'a list holding a number' => [['groups' => ['staff', 1]]];
        yield 'null' => [['email' => null]];
    }

    /**
     * Malformed attributes are refused.
     *
     * @param  array<array-key, mixed>  $attributes
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideMalformedAttributes')]
    public function testRefusesMalformedAttributes(array $attributes): void
    {
        $reference = RequestReference::generate();

        $this->expectExceptionObject(new \InvalidArgumentException('A verified result\'s attributes are strings or lists of strings, each under a non-empty name.'));

        new VerifiedResult('i', 's', null, 'c', 't', 'oidc', 'web', Purpose::SIGN_IN, $reference, $attributes, false, new AuthenticationContext); // @phpstan-ignore argument.type
    }

    /**
     * Strings, lists of strings and the empty list are attributes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAcceptsStringsAndLists(): void
    {
        $attributes = ['email' => 'a@example.com', 'groups' => [], 'roles' => ['a', 'b']];
        $result     = new VerifiedResult('i', 's', null, 'c', 't', 'oidc', 'web', Purpose::SIGN_IN, RequestReference::generate(), $attributes, false, new AuthenticationContext);

        self::assertSame($attributes, $result->attributes);
    }

    /**
     * A result with no asserted email stores no key for one, reads back with
     * none, and may give it as `null` in what it stored.
     *
     * @return void
     */
    public function testAResultWithNoAssertedEmailStoresNone(): void
    {
        $result = ExampleResults::bare();

        self::assertNull($result->assertedEmail);
        self::assertArrayNotHasKey('asserted_email', $result->toArray());
        self::assertArrayNotHasKey('asserted_email', $result->jsonSerialize());
        self::assertNull(VerifiedResult::restore($result->toArray())->assertedEmail);
        self::assertNull(VerifiedResult::restore(['asserted_email' => null] + $result->toArray())->assertedEmail);
    }

    /**
     * Rows of `[verified]`: each thing `email_verified` may be.
     *
     * @return iterable<string, array{0: ?bool}>
     */
    public static function provideAssertions(): iterable
    {
        yield 'verified' => [true];
        yield 'not verified' => [false];
        yield 'unknown' => [null];
    }

    /**
     * The asserted email is stored whole, last, its email and flag exact, and
     * reads back the same through `restore()` and `unserialize()`.
     *
     * @param  ?bool  $verified
     * @return void
     */
    #[DataProvider('provideAssertions')]
    public function testStoresAndReadsBackTheAssertedEmail(?bool $verified): void
    {
        $result = self::aResultAsserting($verified);
        $pair   = ['email' => self::ASSERTED_EMAIL, 'verified' => $verified, 'source' => 'userinfo'];
        $stored = $result->toArray();
        $json   = json_decode((string) json_encode($stored), true);

        self::assertIsArray($json);
        self::assertSame($pair, $stored['asserted_email']);
        self::assertSame('asserted_email', array_key_last($stored));
        self::assertSame($stored, $result->__serialize());
        self::assertSame($pair, VerifiedResult::restore($stored)->assertedEmail?->toArray());
        self::assertSame($stored, VerifiedResult::restore($json)->toArray());

        $unserialised = unserialize(serialize($result));

        self::assertInstanceOf(VerifiedResult::class, $unserialised);
        self::assertSame($pair, $unserialised->assertedEmail?->toArray());
        self::assertSame($stored, $unserialised->toArray());
    }

    /**
     * JSON is the stored form but for the asserted email, which it shows only
     * as its source and flag, in its place.
     *
     * @return void
     */
    public function testJsonShowsTheAssertedEmailRedacted(): void
    {
        $result = self::aResultAsserting(false);

        self::assertSame(array_replace($result->toArray(), ['asserted_email' => ['source' => 'userinfo', 'verified' => false]]), $result->jsonSerialize());
        self::assertStringNotContainsString(self::ASSERTED_PART, (string) json_encode($result));
    }

    /**
     * What JSON writes of an asserted email cannot be read back as one, so a
     * result is never restored from JSON with its email lost.
     *
     * @return void
     */
    public function testTheRedactedJsonIsNotAStoredForm(): void
    {
        $json = json_decode((string) json_encode(self::aResultAsserting(true)), true);

        self::assertIsArray($json);

        $this->expectExceptionObject(new \UnexpectedValueException('A stored verified result is not one the package wrote.'));

        VerifiedResult::restore($json);
    }

    /**
     * No dump of a result shows the asserted email.
     *
     * @return void
     */
    public function testNoDumpOfAResultShowsTheAssertedEmail(): void
    {
        foreach (self::dumps(self::aResultAsserting(true)) as $name => $dump) {
            self::assertStringNotContainsString(self::ASSERTED_PART, $dump, $name);
        }
    }

    /**
     * Claims take the asserted email last and optionally; their JSON adds its
     * redacted form when they have one and no key when they have none, and
     * their dump stays as it was.
     *
     * @return void
     */
    public function testTheClaimsCarryTheAssertedEmailRedacted(): void
    {
        $asserted = new AssertedEmail(self::ASSERTED_EMAIL, null, LinkingEmailSource::ID_TOKEN);
        $bare     = new VerifiedClaims('https://op.example.com', 'sub-1', null, [], new AuthenticationContext);
        $claims   = new VerifiedClaims('https://op.example.com', 'sub-1', null, [], new AuthenticationContext, null, $asserted);

        self::assertNull($bare->assertedEmail);
        self::assertSame($asserted, $claims->assertedEmail);
        self::assertArrayNotHasKey('asserted_email', $bare->jsonSerialize());
        self::assertSame([...$bare->jsonSerialize(), 'asserted_email' => ['source' => 'id_token', 'verified' => null]], $claims->jsonSerialize());
        self::assertSame($bare->__debugInfo(), $claims->__debugInfo());
        self::assertStringNotContainsString(self::ASSERTED_PART, (string) json_encode($claims));

        foreach (self::dumps($claims) as $name => $dump) {
            self::assertStringNotContainsString(self::ASSERTED_PART, $dump, $name);
        }
    }

    /**
     * What claims encode is exactly this: the issuer, the format and the kind
     * of each attribute, never a subject or a value.
     *
     * @return void
     */
    public function testWhatClaimsEncodeIsExact(): void
    {
        $claims = new VerifiedClaims('https://op.example.com', 'sub-1', 'email', ['name' => 'Person'], new AuthenticationContext);

        self::assertSame([
            'issuer'                 => 'https://op.example.com',
            'subject'                => '[redacted]',
            'name_id_format'         => 'email',
            'attributes'             => ['name' => 'string'],
            'authentication_context' => (new AuthenticationContext)->jsonSerialize(),
            'linking_email'          => null,
        ], $claims->jsonSerialize());
    }

    /**
     * An OIDC result with an asserted email and nothing else that holds it.
     *
     * @param  ?bool  $verified
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \InvalidArgumentException
     */
    private static function aResultAsserting(?bool $verified): VerifiedResult
    {
        return new VerifiedResult(
            issuer: 'https://op.example.com',
            subject: 'sub-1',
            nameIdFormat: null,
            connectionId: 'c',
            tenantId: 't',
            protocol: 'oidc',
            application: 'web',
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::fromString(ExampleResults::REFERENCE),
            attributes: ['given_name' => 'Ada'],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext,
            assertedEmail: new AssertedEmail(self::ASSERTED_EMAIL, $verified, LinkingEmailSource::USERINFO),
        );
    }

    /**
     * A result with the parts given and the others valid.
     *
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $format
     * @param  string  $id
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    private static function aResult(string $issuer = 'i', string $subject = 's', ?string $format = null, string $id = 'c'): VerifiedResult
    {
        return new VerifiedResult($issuer, $subject, $format, $id, 't', 'oidc', 'web', Purpose::SIGN_IN, RequestReference::generate(), [], false, new AuthenticationContext);
    }
}
