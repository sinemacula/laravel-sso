<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Saml2\Validation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\SubjectEncoding;

/**
 * Unit tests for the subject a verified SAML identifier is stored as.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectEncoding::class)]
final class SubjectEncodingTest extends TestCase
{
    /** @var string The persistent NameID format. */
    private const string PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /** @var string The basic attribute name format. */
    private const string BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /**
     * A `NameID` with every part is its kind, format, qualifiers and value,
     * each length-prefixed, after the version.
     *
     * @return void
     */
    public function testEncodesANameIdWithEveryPart(): void
    {
        $nameId = new NameId('alice', self::PERSISTENT, 'https://idp.example.test', 'https://sp.example.test', 'ignored');

        self::assertSame(
            'v1|7:name_id|52:' . self::PERSISTENT . '|24:https://idp.example.test|23:https://sp.example.test|5:alice',
            SubjectEncoding::nameId($nameId),
        );
        self::assertSame(['v1', 'name_id', 'attribute'], [SubjectEncoding::VERSION, SubjectEncoding::NAME_ID, SubjectEncoding::ATTRIBUTE]);
    }

    /**
     * An absent format or qualifier is `-`, and an empty one `0:`, so the two
     * are different subjects.
     *
     * @return void
     */
    public function testAnAbsentPartIsNotAnEmptyOne(): void
    {
        $absent = SubjectEncoding::nameId(new NameId('alice'));
        $empty  = SubjectEncoding::nameId(new NameId('alice', '', '', ''));

        self::assertSame('v1|7:name_id|-|-|-|5:alice', $absent);
        self::assertSame('v1|7:name_id|0:|0:|0:|5:alice', $empty);
        self::assertSame('v1|7:name_id|-|-|-|0:', SubjectEncoding::nameId(new NameId('')));
    }

    /**
     * A length is counted in bytes, and a value is kept exactly: never trimmed
     * or case-folded.
     *
     * @return void
     */
    public function testKeepsTheValueExactlyAndCountsBytes(): void
    {
        self::assertSame('v1|7:name_id|-|-|-|8: Älice ', SubjectEncoding::nameId(new NameId(' Älice ')));
        self::assertSame('v1|7:name_id|-|-|-|5:ALICE', SubjectEncoding::nameId(new NameId('ALICE')));
    }

    /**
     * An attribute's subject is its kind, name, name format and the value, the
     * name format `-` when absent.
     *
     * @return void
     */
    public function testEncodesAnAttribute(): void
    {
        $formatted = new SamlAttribute('employeeNumber', self::BASIC, 'Employee', ['E-1', 'E-2']);
        $plain     = new SamlAttribute('employeeNumber');

        self::assertSame('v1|9:attribute|14:employeeNumber|49:' . self::BASIC . '|3:E-1', SubjectEncoding::attribute($formatted, 'E-1'));
        self::assertSame('v1|9:attribute|14:employeeNumber|-|3:E-9', SubjectEncoding::attribute($plain, 'E-9'));
    }

    /**
     * Rows of `[one, other]`: two different identifiers a naive join would make
     * one subject.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideDistinctIdentifiers(): iterable
    {
        yield from [
            'a separator moved between parts' => [
                SubjectEncoding::nameId(new NameId('b', 'a|', null, null)),
                SubjectEncoding::nameId(new NameId('|b', 'a', null, null)),
            ],
            'a qualifier present and absent' => [
                SubjectEncoding::nameId(new NameId('alice', self::PERSISTENT, 'https://idp.example.test')),
                SubjectEncoding::nameId(new NameId('alice', self::PERSISTENT)),
            ],
            'the same text in two qualifiers' => [
                SubjectEncoding::nameId(new NameId('alice', null, 'q', null)),
                SubjectEncoding::nameId(new NameId('alice', null, null, 'q')),
            ],
            'a value that looks like an absent part' => [
                SubjectEncoding::nameId(new NameId('-')),
                SubjectEncoding::nameId(new NameId('', null, null, null)),
            ],
            'a NameID and an attribute of the same value' => [
                SubjectEncoding::nameId(new NameId('alice')),
                SubjectEncoding::attribute(new SamlAttribute('uid'), 'alice'),
            ],
            'two attribute names' => [
                SubjectEncoding::attribute(new SamlAttribute('uid'), 'alice'),
                SubjectEncoding::attribute(new SamlAttribute('UID'), 'alice'),
            ],
        ];
    }

    /**
     * No two different identifiers share an encoding.
     *
     * @param  string  $one
     * @param  string  $other
     * @return void
     */
    #[DataProvider('provideDistinctIdentifiers')]
    public function testDifferentIdentifiersNeverShareAnEncoding(string $one, string $other): void
    {
        self::assertNotSame($one, $other);
    }
}
