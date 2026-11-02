<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlSubject;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\SubjectEncoding;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\SubjectRules;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for the subject of a verified SAML assertion (SSO-6.9): a
 * persistent `NameID` by default, the email and unspecified formats only by
 * opt-in, an absent format only for unspecified, transient never; strict
 * qualifiers; a non-empty value; an attribute subject present once with one
 * non-empty string value; the encoded subject capped at, under and over 1024
 * bytes, never truncated; and an unknown source failing closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectRules::class)]
#[CoversClass(SubjectEncoding::class)]
final class SubjectRulesTest extends TestCase
{
    /** @var string The identity provider's entity id. */
    private const string IDP = 'https://idp.example.test/saml';

    /** @var string The service provider's entity id. */
    private const string SP = 'https://sp.example.test/saml/metadata';

    /** @var string The persistent NameID format. */
    private const string PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /** @var string The email NameID format. */
    private const string EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

    /** @var string The unspecified NameID format. */
    private const string UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

    /** @var string The transient NameID format. */
    private const string TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

    /** @var string The basic attribute name format. */
    private const string BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /**
     * A persistent `NameID` with both qualifiers is the subject, encoded whole,
     * with the persistent format.
     *
     * @return void
     */
    public function testAPersistentNameIdIsTheSubject(): void
    {
        $nameId = new NameId('alice', self::PERSISTENT, self::IDP, self::SP);

        self::assertSame(
            ['v1|7:name_id|52:' . self::PERSISTENT . '|29:' . self::IDP . '|37:' . self::SP . '|5:alice', self::PERSISTENT],
            SubjectRules::subject(self::assertion($nameId), self::context()),
        );
    }

    /**
     * Rows of `[configured, format, accepted]`: the connection's format, the
     * `NameID`'s, and whether it is accepted.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: bool}>
     */
    public static function provideFormats(): iterable
    {
        yield from [
            'persistent by default'                     => [null, self::PERSISTENT, true],
            'email when persistent is configured'       => [null, self::EMAIL, false],
            'unspecified when persistent is configured' => [null, self::UNSPECIFIED, false],
            'transient when persistent is configured'   => [null, self::TRANSIENT, false],
            'no format when persistent is configured'   => [null, null, false],
            'persistent when configured'                => ['persistent', self::PERSISTENT, true],
            'email when configured'                     => ['email', self::EMAIL, true],
            'persistent when email is configured'       => ['email', self::PERSISTENT, false],
            'unspecified when configured'               => ['unspecified', self::UNSPECIFIED, true],
            'no format when unspecified is configured'  => ['unspecified', null, true],
            'transient when unspecified is configured'  => ['unspecified', self::TRANSIENT, false],
            'no format when email is configured'        => ['email', null, false],
            'the format in another case'                => ['persistent', strtoupper(self::PERSISTENT), false],
            'an empty format'                           => ['unspecified', '', false],
        ];
    }

    /**
     * The `NameID`'s format must be the connection's URI exactly, an absent one
     * only for unspecified; transient is never accepted.
     *
     * @param  ?string  $configured
     * @param  ?string  $format
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideFormats')]
    public function testTheFormatMustBeTheConnections(?string $configured, ?string $format, bool $accepted): void
    {
        $settings = $configured === null ? [] : ['name_id_format' => $configured];
        $subject  = SubjectRules::subject(self::assertion(new NameId('alice', $format)), self::context($settings));
        $expected = [SubjectEncoding::nameId(new NameId('alice', $format)), Saml2Options::NAME_ID_FORMATS[$configured ?? 'persistent']];

        self::assertSame($accepted ? $expected : FailureReason::SUBJECT_INVALID, $subject);
    }

    /**
     * Rows of `[nameQualifier, spNameQualifier, accepted]`: the `NameID`'s
     * qualifiers, and whether it is accepted.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: bool}>
     */
    public static function provideQualifiers(): iterable
    {
        yield from [
            'neither'                                   => [null, null, true],
            'the identity provider'                     => [self::IDP, null, true],
            'the service provider'                      => [null, self::SP, true],
            'both'                                      => [self::IDP, self::SP, true],
            'another identity provider'                 => ['https://other.example.test', null, false],
            'another service provider'                  => [null, 'https://other.example.test', false],
            'the identity provider as the SP qualifier' => [null, self::IDP, false],
            'the service provider as the IdP qualifier' => [self::SP, null, false],
            'an empty name qualifier'                   => ['', null, false],
            'an empty SP name qualifier'                => [null, '', false],
            'the identity provider in another case'     => [strtoupper(self::IDP), null, false],
        ];
    }

    /**
     * Each qualifier must be absent or name its party exactly.
     *
     * @param  ?string  $nameQualifier
     * @param  ?string  $spNameQualifier
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideQualifiers')]
    public function testEachQualifierMustBeAbsentOrItsParty(?string $nameQualifier, ?string $spNameQualifier, bool $accepted): void
    {
        $nameId  = new NameId('alice', self::PERSISTENT, $nameQualifier, $spNameQualifier);
        $subject = SubjectRules::subject(self::assertion($nameId), self::context());

        self::assertSame($accepted ? [SubjectEncoding::nameId($nameId), self::PERSISTENT] : FailureReason::SUBJECT_INVALID, $subject);
    }

    /**
     * No subject, a subject with no `NameID`, a base or encrypted identifier,
     * and an empty value are each refused; a value is kept exactly as received.
     *
     * @return void
     */
    public function testANameIdMustBePresentAndNonEmpty(): void
    {
        $context = self::context();

        self::assertSame(FailureReason::SUBJECT_INVALID, SubjectRules::subject(new SamlAssertion('_a', new NameId(self::IDP), self::now()), $context));
        self::assertSame(FailureReason::SUBJECT_INVALID, SubjectRules::subject(self::subjectOf(new SamlSubject(IdentifierKind::NONE)), $context));
        self::assertSame(FailureReason::SUBJECT_INVALID, SubjectRules::subject(self::subjectOf(new SamlSubject(IdentifierKind::BASE_ID)), $context));
        self::assertSame(FailureReason::SUBJECT_INVALID, SubjectRules::subject(self::subjectOf(new SamlSubject(IdentifierKind::ENCRYPTED_ID)), $context));
        self::assertSame(FailureReason::SUBJECT_INVALID, SubjectRules::subject(self::assertion(new NameId('', self::PERSISTENT)), $context));
        self::assertSame(
            ['v1|7:name_id|52:' . self::PERSISTENT . '|-|-|9: Alice@X ', self::PERSISTENT],
            SubjectRules::subject(self::assertion(new NameId(' Alice@X ', self::PERSISTENT)), $context),
        );
    }

    /**
     * The encoded subject may be 1024 bytes and no more; a longer one is
     * refused, never truncated.
     *
     * @return void
     */
    public function testTheEncodedSubjectIsCappedNeverTruncated(): void
    {
        $prefix  = strlen(SubjectEncoding::nameId(new NameId('', self::PERSISTENT)));
        $fits    = str_repeat('a', LinkSubject::MAX_SUBJECT_LENGTH - $prefix - 2);
        $encoded = SubjectEncoding::nameId(new NameId($fits, self::PERSISTENT));

        self::assertSame(1024, strlen($encoded));
        self::assertSame([$encoded, self::PERSISTENT], SubjectRules::subject(self::assertion(new NameId($fits, self::PERSISTENT)), self::context()));
        self::assertSame(FailureReason::SUBJECT_INVALID, SubjectRules::subject(self::assertion(new NameId($fits . 'a', self::PERSISTENT)), self::context()));
    }

    /**
     * An attribute subject is the one value of the one attribute named exactly
     * `subject_attribute`, encoded with its name format, and carries no NameID
     * format; the subject's `NameID` plays no part.
     *
     * @return void
     */
    public function testAnAttributeSubjectIsTheOneValueOfTheOneAttribute(): void
    {
        $attribute = new SamlAttribute('employeeNumber', self::BASIC, null, ['E-1']);
        $assertion = self::assertion(new NameId('t-1', self::TRANSIENT), [new SamlAttribute('email', null, null, ['a@b']), $attribute]);

        self::assertSame(
            ['v1|9:attribute|14:employeeNumber|49:' . self::BASIC . '|3:E-1', null],
            SubjectRules::subject($assertion, self::attributeContext()),
        );
    }

    /**
     * Rows of `[attributes]`: an assertion's attributes with no subject a
     * connection taking `employeeNumber` accepts.
     *
     * @return iterable<string, array{0: list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute>}>
     */
    public static function provideInvalidAttributes(): iterable
    {
        yield from [
            'none'                => [[]],
            'another attribute'   => [[new SamlAttribute('uid', null, null, ['E-1'])]],
            'the name in a case'  => [[new SamlAttribute('EmployeeNumber', null, null, ['E-1'])]],
            'the attribute twice' => [[new SamlAttribute('employeeNumber', null, null, ['E-1']), new SamlAttribute('employeeNumber', null, null, ['E-1'])]],
            'two values'          => [[new SamlAttribute('employeeNumber', null, null, ['E-1', 'E-2'])]],
            'no value'            => [[new SamlAttribute('employeeNumber')]],
            'an empty value'      => [[new SamlAttribute('employeeNumber', null, null, [''])]],
            'a value not text'    => [[new SamlAttribute('employeeNumber', null, null, [null])]],
        ];
    }

    /**
     * An attribute subject is refused unless the attribute is present once with
     * exactly one non-empty string value.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute>  $attributes
     * @return void
     */
    #[DataProvider('provideInvalidAttributes')]
    public function testAnAttributeSubjectMustBePresentOnceWithOneValue(array $attributes): void
    {
        self::assertSame(FailureReason::SUBJECT_INVALID, SubjectRules::subject(self::assertion(new NameId('alice', self::PERSISTENT), $attributes), self::attributeContext()));
    }

    /**
     * An attribute subject longer than 1024 bytes encoded is refused.
     *
     * @return void
     */
    public function testAnAttributeSubjectIsCapped(): void
    {
        $prefix = strlen(SubjectEncoding::attribute(new SamlAttribute('employeeNumber'), ''));
        $fits   = str_repeat('e', LinkSubject::MAX_SUBJECT_LENGTH - $prefix - 2);

        self::assertSame(
            [SubjectEncoding::attribute(new SamlAttribute('employeeNumber'), $fits), null],
            SubjectRules::subject(self::assertion(null, [new SamlAttribute('employeeNumber', null, null, [$fits])]), self::attributeContext()),
        );
        self::assertSame(
            FailureReason::SUBJECT_INVALID,
            SubjectRules::subject(self::assertion(null, [new SamlAttribute('employeeNumber', null, null, [$fits . 'e'])]), self::attributeContext()),
        );
    }

    /**
     * An attribute source with no attribute named, and a source the package
     * does not know, each fail closed.
     *
     * @return void
     */
    public function testAnUnknownOrIncompleteSourceFailsClosed(): void
    {
        $assertion = self::assertion(new NameId('alice', self::PERSISTENT), [new SamlAttribute('employeeNumber', null, null, ['E-1'])]);
        $unknown   = new Saml2Options(self::IDP, null, 'http_redirect', 'other', 'employeeNumber', 'persistent', [], [], null, null, null);
        $unnamed   = new Saml2Options(self::IDP, null, 'http_redirect', 'attribute', null, 'persistent', [], [], null, null, null);

        self::assertSame(FailureReason::SUBJECT_INVALID, SubjectRules::subject($assertion, self::contextOf($unknown)));
        self::assertSame(FailureReason::SUBJECT_INVALID, SubjectRules::subject($assertion, self::contextOf($unnamed)));
    }

    /**
     * An assertion whose subject carries the `NameID`, or none, with the
     * attributes.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $nameId
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute>  $attributes
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function assertion(?NameId $nameId, array $attributes = []): SamlAssertion
    {
        $subject = new SamlSubject($nameId === null ? IdentifierKind::NONE : IdentifierKind::NAME_ID, $nameId);

        return new SamlAssertion('_assertion-1', new NameId(self::IDP), self::now(), $subject, null, [], $attributes);
    }

    /**
     * An assertion with the subject.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlSubject  $subject
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function subjectOf(SamlSubject $subject): SamlAssertion
    {
        return new SamlAssertion('_assertion-1', new NameId(self::IDP), self::now(), $subject);
    }

    /**
     * The context of a connection taking its subject from `employeeNumber`.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     */
    private static function attributeContext(): ValidationContext
    {
        return self::context(['subject_source' => 'attribute', 'subject_attribute' => 'employeeNumber']);
    }

    /**
     * The context of a connection with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     */
    private static function context(array $settings = []): ValidationContext
    {
        return self::contextOf(Saml2Options::of(new ExampleConnection('saml2', ['idp_entity_id' => self::IDP, ...$settings])));
    }

    /**
     * The context of a connection with the options.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     */
    private static function contextOf(Saml2Options $options): ValidationContext
    {
        return new ValidationContext('01jbexampleconnection00000', $options, 'https://sp.example.test/saml/acs', self::SP, self::now(), 60, 300);
    }

    /**
     * The instant every rule is judged at.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function now(): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-11-01T09:30:00Z');
    }
}
