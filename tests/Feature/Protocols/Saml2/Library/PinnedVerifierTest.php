<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\samlp\Response;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\PinnedVerifier;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\TestCase;

/**
 * Tests of the element the pinned verifier answers with a verified signed
 * element (SSO-6.3, `saml-library.md` condition 3): parsed from exactly the
 * bytes the library digested, the signature removed, in a document of its own,
 * so a change to the document it was read from after verification never reaches
 * it; and nothing answered for an element no trusted certificate verifies.
 *
 * The library is named here only to build the signed elements the verifier
 * takes, as the adapter builds them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PinnedVerifier::class)]
final class PinnedVerifierTest extends TestCase
{
    /** @var string The SAML assertion namespace. */
    private const string NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** @var string The XML signature namespace. */
    private const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /**
     * A signed assertion's verified element is its digested bytes: the
     * assertion without its signature, canonicalised, in a document of its own,
     * and the object verified with it is the assertion; removing a child from
     * the document it was read from afterwards leaves it whole.
     *
     * @return void
     *
     * @throws \Exception
     */
    public function testAnAssertionsVerifiedElementIsWhatItsSignatureDigested(): void
    {
        $document = self::document(self::idp()->response('https://sp.example.test/saml', 'https://sp.example.test/acs')->signed(false, true)->toXml());
        $original = self::reRooted(self::child($document->documentElement, self::NS_SAML, 'Assertion'));

        [$assertion, $element] = app(PinnedVerifier::class)->verifiedElement(Assertion::fromXML($original), [self::idp()->certificate()], PinnedVerifier::SIGNATURE_ALGORITHMS);

        self::assertSame($original->getAttribute('ID'), $assertion->getId()->getRawValue());
        self::assertSame(self::unsigned($original), $element->C14N(true, false));
        self::assertNotSame($original->ownerDocument, $element->ownerDocument);
        self::assertSame([self::NS_SAML, 'Assertion', null], [$element->namespaceURI, $element->localName, self::child($element, self::NS_DS, 'Signature', false)]);

        $conditions = self::child($original, self::NS_SAML, 'Conditions');

        $original->removeChild($conditions);

        self::assertNotNull(self::child($element, self::NS_SAML, 'Conditions', false));
    }

    /**
     * A signed response's verified element is the response without its
     * signature, its one assertion inside it.
     *
     * @return void
     *
     * @throws \Exception
     */
    public function testAResponsesVerifiedElementHoldsTheAssertionItCovers(): void
    {
        $document = self::document(self::idp()->response('https://sp.example.test/saml', 'https://sp.example.test/acs')->signed(true, false)->toXml());
        $root     = $document->documentElement;

        self::assertNotNull($root);

        [$response, $element] = app(PinnedVerifier::class)->verifiedElement(Response::fromXML($root), [self::idp()->certificate()], PinnedVerifier::SIGNATURE_ALGORITHMS);

        self::assertSame($root->getAttribute('ID'), $response->getId()->getRawValue());
        self::assertSame(self::unsigned($root), $element->C14N(true, false));
        self::assertNull(self::child($element, self::NS_DS, 'Signature', false));
        self::assertNotNull(self::child($element, self::NS_SAML, 'Assertion', false));
    }

    /**
     * An element no trusted certificate verifies is refused with the reason
     * given, and no element is answered.
     *
     * @return void
     *
     * @throws \Exception
     */
    public function testAnElementNoTrustedCertificateVerifiesIsRefused(): void
    {
        $document = self::document(self::idp()->response('https://sp.example.test/saml', 'https://sp.example.test/acs')->signed(false, true)->toXml());
        $original = self::reRooted(self::child($document->documentElement, self::NS_SAML, 'Assertion'));
        $stranger = (new FakeSamlIdentityProvider('https://stranger.example.test/saml'))->certificate();

        try {
            $verifier = app(PinnedVerifier::class);

            $verifier->verifiedElement(Assertion::fromXML($original), [$stranger], PinnedVerifier::SIGNATURE_ALGORITHMS, FailureReason::METADATA_SIGNATURE_INVALID);
            self::fail('An element no trusted certificate verifies was answered.');
        } catch (ReadFailure $failure) {
            self::assertSame([FailureReason::METADATA_SIGNATURE_INVALID, 'signature'], [$failure->reason, $failure->detail]);
        }
    }

    /**
     * The XML parsed into a document.
     *
     * @param  string  $xml
     * @return \DOMDocument
     */
    private static function document(string $xml): \DOMDocument
    {
        $document = new \DOMDocument;

        self::assertTrue($document->loadXML($xml));

        return $document;
    }

    /**
     * The element copied into a document of its own, as the adapter re-roots an
     * assertion.
     *
     * @param  \DOMElement  $element
     * @return \DOMElement
     *
     * @throws \DOMException
     */
    private static function reRooted(\DOMElement $element): \DOMElement
    {
        $document = new \DOMDocument('1.0', 'UTF-8');
        $copy     = $document->importNode($element, true);

        self::assertInstanceOf(\DOMElement::class, $copy);

        $document->appendChild($copy);

        return $copy;
    }

    /**
     * The element's exclusive canonical form without its own signature, worked
     * out apart from the verifier.
     *
     * @param  \DOMElement  $element
     * @return string
     *
     * @throws \DOMException
     */
    private static function unsigned(\DOMElement $element): string
    {
        $copy = self::reRooted($element);

        $copy->removeChild(self::child($copy, self::NS_DS, 'Signature'));

        return (string) $copy->C14N(true, false);
    }

    /**
     * The element's first child of the name, required unless said otherwise.
     *
     * @param  ?\DOMElement  $element
     * @param  string  $namespace
     * @param  string  $name
     * @param  bool  $required
     * @return ?\DOMElement
     *
     * @phpstan-return ($required is true ? \DOMElement : ?\DOMElement)
     */
    private static function child(?\DOMElement $element, string $namespace, string $name, bool $required = true): ?\DOMElement
    {
        foreach ($element->childNodes ?? [] as $child) {
            if ($child instanceof \DOMElement && $child->namespaceURI === $namespace && $child->localName === $name) {
                return $child;
            }
        }

        if ($required) {
            self::fail("No {$name} child.");
        }

        return null;
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
