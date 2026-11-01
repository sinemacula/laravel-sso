<?php

declare(strict_types = 1);

namespace Tests\Unit\Links;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Unit tests for what a link is keyed by (SSO-8.2, SSO-6.9): the key pinned by
 * vectors computed independently of the package, a missing and a set format,
 * case and a trailing space each giving another key, the byte bounds of each
 * part, the subject a verified result names, and comparison byte for byte.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkSubject::class)]
final class LinkSubjectTest extends TestCase
{
    /** @var string The issuer every vector uses. */
    private const string ISSUER = 'https://idp.example.com';

    /** @var string The format the SAML vectors use. */
    private const string FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /**
     * Rows of `[issuer, subject, format, key]`: keys computed outside the
     * package, as the SHA-256 of `sso-link-v1`, a NUL byte, the issuer, `N` or
     * `F` and the format, and the subject, each part prefixed with its length
     * as four big-endian bytes.
     *
     * @return iterable<string, array{string, string, ?string, string}>
     */
    public static function provideVectors(): iterable
    {
        yield 'a SAML subject with its format' => [self::ISSUER, 'Subject 1', self::FORMAT, 'bb5825fffcf4bb035d2ed0c1612e8d4048d91940496c8428f4e0b8bd1b302f1c'];
        yield 'the same subject with no format' => [self::ISSUER, 'Subject 1', null, 'dd8d9e75168470d7306ea5f63e670d01a0ef227444825cb53fa9b66fdeb81bd8'];
        yield 'the subject in lower case' => [self::ISSUER, 'subject 1', self::FORMAT, '6c003691ff0b520291f096842489d92773e9d2b11c7ab169219146e8a49a5709'];
        yield 'the subject with a trailing space' => [self::ISSUER, 'Subject 1 ', self::FORMAT, '46a52b919352fd5391e8a9291e1aee45672b0468f6e153c26f799d8da0c57793'];
        yield 'one-byte parts' => ['a', 'b', null, 'd1d740dbc56e21a35fc1d1ac9c4b524fe00c4d16621e29d36e87f1c185ee28d6'];
        yield 'a byte moved from the issuer to the subject' => ['ab', 'c', null, '373295a01976cffb4255e7ce1e86dd42dc06eabbccd0d0a3d756fd54713605cc'];
        yield 'a byte moved from the subject to the issuer' => ['a', 'bc', null, '473b97cc123f42fe01c3d4938b2e92fc553720e6ebf36f17921090fd8c6d03d8'];
    }

    /**
     * The key is the vector computed independently.
     *
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $format
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideVectors')]
    public function testTheKeyIsTheIndependentVector(string $issuer, string $subject, ?string $format, string $key): void
    {
        self::assertSame($key, (new LinkSubject($issuer, $subject, $format))->key());
    }

    /**
     * Every vector's key differs from every other's: no format and a set one,
     * case, a trailing space and where the bytes fall each give another key.
     *
     * @return void
     */
    public function testEveryVectorHasItsOwnKey(): void
    {
        $keys = array_map(static fn (array $vector): string => $vector[3], iterator_to_array(self::provideVectors(), false));

        self::assertCount(7, array_unique($keys));
    }

    /**
     * The subject a verified result names is its issuer, subject and format,
     * kept exactly, a trailing space included.
     *
     * @return void
     */
    public function testOfTakesTheResultsIssuerSubjectAndFormat(): void
    {
        $saml = LinkSubject::of(ExampleResults::full());
        $oidc = LinkSubject::of(ExampleResults::bare());

        self::assertSame(['https://idp.example.com', 'Subject 1 ', self::FORMAT], [$saml->issuer, $saml->subject, $saml->nameIdFormat]);
        self::assertSame(['https://op.example.com', 'sub-1', null], [$oidc->issuer, $oidc->subject, $oidc->nameIdFormat]);
    }

    /**
     * Rows of `[issuer, subject, format]`: each part at its longest.
     *
     * @return iterable<string, array{string, string, ?string}>
     */
    public static function provideLongest(): iterable
    {
        yield 'an issuer of 1024 bytes' => [str_repeat('i', 1024), 's', null];
        yield 'a subject of 1024 bytes' => ['i', str_repeat('s', 1024), null];
        yield 'a format of 255 bytes' => ['i', 's', str_repeat('f', 255)];
        yield 'one byte each' => ['i', 's', 'f'];
    }

    /**
     * Each part is accepted at its longest, and at one byte.
     *
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $format
     * @return void
     */
    #[DataProvider('provideLongest')]
    public function testEachPartIsAcceptedUpToItsLongest(string $issuer, string $subject, ?string $format): void
    {
        $linkSubject = new LinkSubject($issuer, $subject, $format);

        self::assertSame([$issuer, $subject, $format], [$linkSubject->issuer, $linkSubject->subject, $linkSubject->nameIdFormat]);
    }

    /**
     * Rows of `[issuer, subject, format, message]`: each part empty, and one
     * byte too long.
     *
     * @return iterable<string, array{string, string, ?string, string}>
     */
    public static function provideRefused(): iterable
    {
        yield 'an empty issuer' => ['', 's', null, 'A link\'s issuer is 1 to 1024 bytes.'];
        yield 'an issuer of 1025 bytes' => [str_repeat('i', 1025), 's', null, 'A link\'s issuer is 1 to 1024 bytes.'];
        yield 'an empty subject' => ['i', '', null, 'A link\'s subject is 1 to 1024 bytes.'];
        yield 'a subject of 1025 bytes' => ['i', str_repeat('s', 1025), null, 'A link\'s subject is 1 to 1024 bytes.'];
        yield 'an empty format' => ['i', 's', '', 'A link\'s NameID format is 1 to 255 bytes.'];
        yield 'a format of 256 bytes' => ['i', 's', str_repeat('f', 256), 'A link\'s NameID format is 1 to 255 bytes.'];
    }

    /**
     * An empty part, or one a byte too long, is refused with a message that
     * names the part and its bounds, never the value.
     *
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $format
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefused')]
    public function testAPartOutOfBoundsIsRefused(string $issuer, string $subject, ?string $format, string $message): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException($message));

        new LinkSubject($issuer, $subject, $format);
    }

    /**
     * A subject is another only when every part is equal byte for byte.
     *
     * @return void
     */
    public function testIsComparesEveryPartByteForByte(): void
    {
        $subject = new LinkSubject(self::ISSUER, 'Subject 1', self::FORMAT);

        self::assertTrue($subject->is(new LinkSubject(self::ISSUER, 'Subject 1', self::FORMAT)));
        self::assertFalse($subject->is(new LinkSubject(self::ISSUER . '/', 'Subject 1', self::FORMAT)));
        self::assertFalse($subject->is(new LinkSubject(self::ISSUER, 'Subject 1 ', self::FORMAT)));
        self::assertFalse($subject->is(new LinkSubject(self::ISSUER, 'subject 1', self::FORMAT)));
        self::assertFalse($subject->is(new LinkSubject(self::ISSUER, 'Subject 1')));
        self::assertFalse($subject->is(new LinkSubject(self::ISSUER, 'Subject 1', self::FORMAT . ':v2')));
    }
}
