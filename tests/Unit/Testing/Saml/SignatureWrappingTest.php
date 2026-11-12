<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Saml;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use SineMacula\Laravel\Sso\Testing\Saml\SignatureWrapping;
use Tests\Concerns\OutlinesSamlDocuments;

/**
 * Unit tests for the fake identity provider's signature wrapping attacks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignatureWrapping::class)]
final class SignatureWrappingTest extends TestCase
{
    use OutlinesSamlDocuments;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /**
     * The variant lists name every variant, and the two that wrap a signed
     * response.
     *
     * @return void
     */
    public function testListsItsVariants(): void
    {
        self::assertSame(['xsw1', 'xsw2', 'xsw3', 'xsw4', 'xsw5', 'xsw6', 'xsw7', 'xsw8', 'same_id_before', 'same_id_after'], SignatureWrapping::VARIANTS);
        self::assertSame(['xsw1', 'xsw2'], SignatureWrapping::RESPONSE_VARIANTS);
    }

    /**
     * Rows of `[variant, outline]`: each variant, and the outline of the
     * response it wraps.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideVariants(): iterable
    {
        yield from [
            'xsw1'           => ['xsw1', 'Response#_evil-response{Signature{Response#_response{Assertion#_assertion}},Assertion#_assertion}'],
            'xsw2'           => ['xsw2', 'Response#_evil-response{Response#_response{Assertion#_assertion},Signature,Assertion#_assertion}'],
            'xsw3'           => ['xsw3', 'Response#_response{Assertion#_evil-assertion,Assertion#_assertion{Signature}}'],
            'xsw4'           => ['xsw4', 'Response#_response{Assertion#_evil-assertion{Assertion#_assertion{Signature}}}'],
            'xsw5'           => ['xsw5', 'Response#_response{Assertion#_evil-assertion{Signature},Assertion#_assertion}'],
            'xsw6'           => ['xsw6', 'Response#_response{Assertion#_evil-assertion{Signature{Assertion#_assertion}}}'],
            'xsw7'           => ['xsw7', 'Response#_response{Extensions{Assertion#_assertion{Signature}},Assertion#_evil-assertion}'],
            'xsw8'           => ['xsw8', 'Response#_response{Assertion#_evil-assertion{Signature{Object{Assertion#_assertion}}}}'],
            'same_id_before' => ['same_id_before', 'Response#_response{Assertion#_assertion,Assertion#_assertion{Signature}}'],
            'same_id_after'  => ['same_id_after', 'Response#_response{Assertion#_assertion{Signature},Assertion#_assertion}'],
        ];
    }

    /**
     * Each variant moves the signed element, its signature and the evil element
     * where the attack it names puts them.
     *
     * @param  string  $variant
     * @param  string  $outline
     * @return void
     */
    #[DataProvider('provideVariants')]
    public function testWrapsAsTheVariantSays(string $variant, string $outline): void
    {
        self::assertSame($outline, self::outline(self::response()->wrapped($variant)->toXml()));
    }

    /**
     * The evil element carries the evil subject and the signed one the real
     * subject, in each variant's document order.
     *
     * @return void
     */
    public function testTheEvilElementCarriesTheEvilSubject(): void
    {
        self::assertSame(['alice', 'mallory'], self::nameIds(self::response()->wrapped('xsw1')->toXml()));
        self::assertSame(['mallory', 'alice'], self::nameIds(self::response()->wrapped('xsw3')->toXml()));
        self::assertSame(['alice', 'mallory'], self::nameIds(self::response()->wrapped('same_id_after')->toXml()));
    }

    /**
     * A response to wrap that lacks the element a variant moves is refused,
     * naming what it lacks.
     *
     * @return void
     */
    public function testRefusesADocumentWithoutTheElementToMove(): void
    {
        $document = new \DOMDocument;

        $document->loadXML('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>');

        $this->expectExceptionObject(new \LogicException('The element to wrap has no Assertion.'));

        (new SignatureWrapping)->apply('xsw3', $document, '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>');
    }

    /**
     * The `NameID`s of the XML, in document order.
     *
     * @param  string  $xml
     * @return list<string>
     */
    private static function nameIds(string $xml): array
    {
        $document = new \DOMDocument;

        $document->loadXML($xml);

        $names = [];

        foreach ($document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'NameID') as $nameId) {
            $names[] = $nameId->textContent;
        }

        return $names;
    }

    /**
     * A response from the provider with fixed identifiers.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private static function response(): FakeSamlResponse
    {
        self::$idp ??= new FakeSamlIdentityProvider;

        return self::$idp->response('https://sp.example.test', 'https://sp.example.test/acs', CarbonImmutable::parse('2026-11-01T12:00:00Z'))
            ->with(['response_id' => '_response', 'assertion_id' => '_assertion']);
    }
}
