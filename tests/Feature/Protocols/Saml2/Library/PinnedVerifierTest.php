<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SimpleSAML\SAML2\XML\md\AbstractSignedMdElement;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XML\Type\IDValue;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\XML\ds\Signature;
use SimpleSAML\XMLSecurity\XML\SignedElementInterface;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\PinnedVerifier;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SignedDescriptor;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\TestCase;

/**
 * Tests of the element the pinned verifier answers for a verified signed
 * element.
 *
 * The library is named here only to build signed elements as the adapter does.
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
     * A signed assertion's verified element is its digested bytes in a document
     * of its own, unaffected by later changes.
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
     * A signed descriptor's verified element is its entity without the
     * signature, in a document of its own.
     *
     * @return void
     *
     * @throws \Exception
     */
    public function testADescriptorsVerifiedElementIsItsEntityUnsigned(): void
    {
        $root = self::document(self::idp()->metadata()->with(['sign' => 'entity'])->toXml())->documentElement;

        self::assertNotNull($root);

        [$descriptor, $element] = app(PinnedVerifier::class)->verifiedElement(SignedDescriptor::fromXML($root), [self::idp()->certificate()], PinnedVerifier::SIGNATURE_ALGORITHMS);

        self::assertSame($root->getAttribute('ID'), $descriptor->getId()?->getValue());
        self::assertSame(self::unsigned($root), $element->C14N(true, false));
        self::assertNull(self::child($element, self::NS_DS, 'Signature', false));
        self::assertNotSame($root->ownerDocument, $element->ownerDocument);
    }

    /**
     * A signed element with no `ID` for its reference to name is refused before
     * its signature is verified.
     *
     * @return void
     */
    public function testAnElementWithNoIdIsRefusedBeforeVerifying(): void
    {
        $xml  = (string) preg_replace('/(<md:EntityDescriptor[^>]*?) ID="[^"]+"/', '$1', self::idp()->metadata()->with(['sign' => 'entity'])->toXml());
        $root = self::document($xml)->documentElement;

        self::assertNotNull($root);

        try {
            app(PinnedVerifier::class)->verified(SignedDescriptor::fromXML($root), [self::idp()->certificate()], PinnedVerifier::SIGNATURE_ALGORITHMS);
            self::fail('An element with no ID was verified.');
        } catch (ReadFailure $failure) {
            self::assertSame([FailureReason::SIGNATURE_INVALID, 'signature_policy'], [$failure->reason, $failure->detail]);
        }
    }

    /**
     * An element whose digested bytes cannot be rebuilt is refused with the
     * reason given, however it verified.
     *
     * @return void
     */
    public function testAnElementWhoseDigestCannotBeRebuiltIsRefused(): void
    {
        $xml  = (string) preg_replace('#<ds:Transforms>.*?</ds:Transforms>#s', '', self::idp()->metadata()->with(['sign' => 'entity'])->toXml());
        $root = self::document($xml)->documentElement;

        self::assertNotNull($root);

        try {
            $verifier = app(PinnedVerifier::class);

            $verifier->verifiedElement(self::alwaysVerified($root), [self::idp()->certificate()], PinnedVerifier::SIGNATURE_ALGORITHMS, FailureReason::METADATA_SIGNATURE_INVALID);
            self::fail('An element whose digest cannot be rebuilt was answered.');
        } catch (ReadFailure $failure) {
            self::assertSame([FailureReason::METADATA_SIGNATURE_INVALID, 'signature'], [$failure->reason, $failure->detail]);
        }
    }

    /**
     * Rows of `[transforms]`: the transforms of a reference the trusted key
     * signs over the same digested bytes, which the library would verify.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideDisallowedTransforms(): iterable
    {
        yield 'another transform' => [['enveloped', 'exc-c14n-comments']];
        yield 'a transform listed twice' => [['exc-c14n', 'exc-c14n']];
    }

    /**
     * A reference with a disallowed or repeated transform is refused before its
     * signature is verified.
     *
     * @param  list<string>  $transforms
     * @return void
     *
     * @throws \Exception
     */
    #[DataProvider('provideDisallowedTransforms')]
    public function testAReferenceListsOnlyTheAllowedTransformsOnce(array $transforms): void
    {
        $verifier = app(PinnedVerifier::class);

        $allowed = $verifier->verified(self::signedWith(['enveloped', 'exc-c14n']), [self::idp()->certificate()], PinnedVerifier::SIGNATURE_ALGORITHMS);

        self::assertSame('_signed', $allowed->getId()->getRawValue());

        try {
            $verifier->verified(self::signedWith($transforms), [self::idp()->certificate()], PinnedVerifier::SIGNATURE_ALGORITHMS);
            self::fail('A reference with a transform the policy does not allow was verified.');
        } catch (ReadFailure $failure) {
            self::assertSame([FailureReason::SIGNATURE_INVALID, 'signature_policy'], [$failure->reason, $failure->detail]);
        }
    }

    /**
     * An assertion the trusted identity provider signs, its reference listing
     * the transforms given, alone in a document of its own.
     *
     * @param  list<string>  $transforms
     * @return \SimpleSAML\SAML2\XML\saml\Assertion
     *
     * @throws \Exception
     */
    private static function signedWith(array $transforms): Assertion
    {
        $response  = self::idp()->response('https://sp.example.test/saml', 'https://sp.example.test/acs')->signed(false, false);
        $document  = self::document($response->with(['assertion_id' => '_signed'])->toXml());
        $assertion = self::reRooted(self::child($document->documentElement, self::NS_SAML, 'Assertion'));

        self::idp()->signer()->sign($assertion, ['transforms' => $transforms]);

        return Assertion::fromXML($assertion);
    }

    /**
     * The signed descriptor as an element that claims to verify under any key.
     *
     * @param  \DOMElement  $xml
     * @return \SimpleSAML\SAML2\XML\md\AbstractSignedMdElement
     */
    private static function alwaysVerified(\DOMElement $xml): AbstractSignedMdElement
    {
        return new class ($xml) extends AbstractSignedMdElement {
            /**
             * Constructor.
             *
             * @param  \DOMElement  $xml
             */
            public function __construct(\DOMElement $xml)
            {
                $this->setSignature(Signature::getChildrenOfClass($xml)[0]);
                $this->setXML($xml);
            }

            /**
             * Never called by the verifier.
             *
             * @param  \DOMElement  $xml
             * @return static
             *
             * @throws \LogicException
             */
            #[\Override]
            public static function fromXML(\DOMElement $xml): static
            {
                throw new \LogicException('The verifier called fromXML().');
            }

            /**
             * The element's `ID`.
             *
             * @return \SimpleSAML\XML\Type\IDValue
             */
            #[\Override]
            public function getId(): IDValue
            {
                return IDValue::fromString($this->xml->getAttribute('ID'));
            }

            /**
             * The element it was read from.
             *
             * @param  ?\DOMElement  $parent
             * @return \DOMElement
             */
            #[\Override]
            public function toUnsignedXML(?\DOMElement $parent = null): \DOMElement
            {
                return $this->xml;
            }

            /**
             * Itself, whatever the key.
             *
             * @param  ?\SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface  $verifier
             * @return \SimpleSAML\XMLSecurity\XML\SignedElementInterface
             */
            #[\Override]
            public function verify(?SignatureAlgorithmInterface $verifier = null): SignedElementInterface
            {
                return $this;
            }

            /**
             * The element it was read from.
             *
             * @return \DOMElement
             */
            #[\Override]
            protected function getOriginalXML(): \DOMElement
            {
                return $this->xml;
            }
        };
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
