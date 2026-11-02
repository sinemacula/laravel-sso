<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Saml;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\XmlSigner;

/**
 * Unit tests for the enveloped signature the fake SAML identity provider
 * writes: the exact `SignedInfo` (canonicalisation, signature method,
 * reference, transforms, digest method and the digest of the exclusive
 * canonical bytes, comments left out), a signature value that verifies with the
 * provider's certificate, the `KeyInfo` carrying it, where the signature goes,
 * and each option changing just its part.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(XmlSigner::class)]
final class XmlSignerTest extends TestCase
{
    /** @var string The document signed: a namespace it never uses, an issuer, a comment, and a body. */
    private const string DOCUMENT = '<r:Root xmlns:r="urn:r" xmlns:unused="urn:unused" ID="_root"><r:Issuer>i</r:Issuer><!-- note --><r:Body ID="_body">text</r:Body></r:Root>';

    /** @var string The root's exclusive canonical form, without comments. */
    private const string CANONICAL_ROOT = '<r:Root xmlns:r="urn:r" ID="_root"><r:Issuer>i</r:Issuer><r:Body ID="_body">text</r:Body></r:Root>';

    /** @var string The body's exclusive canonical form. */
    private const string CANONICAL_BODY = '<r:Body xmlns:r="urn:r" ID="_body">text</r:Body>';

    /** @var string Exclusive canonicalisation. */
    private const string EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /** @var string RSA-SHA256. */
    private const string RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    /** @var string SHA-256. */
    private const string SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

    /** @var ?array{0: string, 1: string} The private key and certificate, made once. */
    private static ?array $keys = null;

    /**
     * By default the signature references the element by its `ID`, digests its
     * exclusive canonical form without comments with SHA-256, signs with
     * RSA-SHA256, carries the certificate, and goes right after the issuer.
     *
     * @return void
     */
    public function testSignsTheElementByDefault(): void
    {
        $document  = self::document();
        $root      = self::root($document);
        $signature = self::signer()->sign($root);

        self::assertSame($root, $signature->parentNode);
        self::assertSame('Issuer', $signature->previousSibling?->localName);
        self::assertSame(XML_COMMENT_NODE, $signature->nextSibling?->nodeType);
        self::assertSame(['SignedInfo', 'SignatureValue', 'KeyInfo'], self::childNames($signature));
        self::assertSame(
            self::signedInfo(self::EXC_C14N, self::RSA_SHA256, '#_root', self::SHA256, self::digest('sha256', self::CANONICAL_ROOT)),
            self::canonicalSignedInfo($signature),
        );
        self::assertSame(1, self::verify($signature, OPENSSL_ALGO_SHA256));
        self::assertSame(self::certificateBody(), self::text($signature, 'X509Certificate'));
        self::assertSame(['X509Data'], self::childNames(self::childNamed($signature, 'KeyInfo')));
    }

    /**
     * A target references and digests that element instead of the one the
     * signature goes in.
     *
     * @return void
     */
    public function testDigestsTheTarget(): void
    {
        $document  = self::document();
        $root      = self::root($document);
        $body      = self::childNamed($root, 'Body');
        $signature = self::signer()->sign($root, ['target' => $body]);

        self::assertSame($root, $signature->parentNode);
        self::assertSame(
            self::signedInfo(self::EXC_C14N, self::RSA_SHA256, '#_body', self::SHA256, self::digest('sha256', self::CANONICAL_BODY)),
            self::canonicalSignedInfo($signature),
        );
    }

    /**
     * An empty reference digests the whole document, even when the element
     * signed is another, and an element with no issuer takes the signature as
     * its first child.
     *
     * @return void
     */
    public function testAnEmptyReferenceDigestsTheWholeDocument(): void
    {
        $document  = self::document();
        $body      = self::childNamed(self::root($document), 'Body');
        $signature = self::signer()->sign($body, ['uri' => '']);

        self::assertSame($signature, $body->firstChild);
        self::assertSame('text', $signature->nextSibling?->textContent);
        self::assertSame(
            self::signedInfo(self::EXC_C14N, self::RSA_SHA256, '', self::SHA256, self::digest('sha256', self::CANONICAL_ROOT)),
            self::canonicalSignedInfo($signature),
        );
    }

    /**
     * The algorithm, digest and comments options change the signature method,
     * the digest and the canonicalisation the `SignedInfo` names, and the value
     * verifies with the algorithm's hash.
     *
     * @return void
     */
    public function testSignsWithTheAlgorithmsGiven(): void
    {
        $signature = self::signer()->sign(self::root(self::document()), ['algorithm' => 'rsa-sha512', 'digest' => 'sha512', 'comments' => true]);

        self::assertSame(
            self::signedInfo(
                'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
                'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
                '#_root',
                'http://www.w3.org/2001/04/xmlenc#sha512',
                self::digest('sha512', self::CANONICAL_ROOT),
            ),
            self::canonicalSignedInfo($signature),
        );
        self::assertSame(1, self::verify($signature, OPENSSL_ALGO_SHA512));
        self::assertSame(0, self::verify($signature, OPENSSL_ALGO_SHA256));
    }

    /**
     * An element with no children takes the signature as its only child.
     *
     * @return void
     */
    public function testSignsAnEmptyElement(): void
    {
        $document = new \DOMDocument;

        $document->loadXML('<r:Root xmlns:r="urn:r" ID="_empty"/>');

        $root      = self::root($document);
        $signature = self::signer()->sign($root);

        self::assertSame([$signature], iterator_to_array($root->childNodes));
        self::assertSame(1, self::verify($signature, OPENSSL_ALGO_SHA256));
    }

    /**
     * An element that belongs to no document cannot be signed.
     *
     * @return void
     *
     * @throws \DOMException
     */
    public function testRefusesAnElementOutsideADocument(): void
    {
        $this->expectExceptionObject(new \LogicException('The element to sign belongs to a document.'));

        self::signer()->sign(new \DOMElement('orphan'));
    }

    /**
     * The `SignedInfo` the tests expect, in exclusive canonical form.
     *
     * @param  string  $canonicalisation
     * @param  string  $method
     * @param  string  $uri
     * @param  string  $digestMethod
     * @param  string  $digest
     * @return string
     */
    private static function signedInfo(string $canonicalisation, string $method, string $uri, string $digestMethod, string $digest): string
    {
        return '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            . '<ds:CanonicalizationMethod Algorithm="' . $canonicalisation . '"></ds:CanonicalizationMethod>'
            . '<ds:SignatureMethod Algorithm="' . $method . '"></ds:SignatureMethod>'
            . '<ds:Reference URI="' . $uri . '"><ds:Transforms>'
            . '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>'
            . '<ds:Transform Algorithm="' . self::EXC_C14N . '"></ds:Transform>'
            . '</ds:Transforms>'
            . '<ds:DigestMethod Algorithm="' . $digestMethod . '"></ds:DigestMethod>'
            . '<ds:DigestValue>' . $digest . '</ds:DigestValue>'
            . '</ds:Reference></ds:SignedInfo>';
    }

    /**
     * The signature's `SignedInfo` in exclusive canonical form.
     *
     * @param  \DOMElement  $signature
     * @return string
     */
    private static function canonicalSignedInfo(\DOMElement $signature): string
    {
        return (string) self::childNamed($signature, 'SignedInfo')->C14N(true);
    }

    /**
     * Whether the signature value verifies over the canonical `SignedInfo` with
     * the certificate and hash: 1 when it does, 0 when it does not.
     *
     * @param  \DOMElement  $signature
     * @param  int  $hash
     * @return false|int
     */
    private static function verify(\DOMElement $signature, int $hash): false|int
    {
        $value = (string) base64_decode(self::text($signature, 'SignatureValue'), true);

        return openssl_verify(self::canonicalSignedInfo($signature), $value, self::keys()[1], $hash);
    }

    /**
     * The base64 digest of the bytes with the hash.
     *
     * @param  string  $hash
     * @param  string  $bytes
     * @return string
     */
    private static function digest(string $hash, string $bytes): string
    {
        return base64_encode(hash($hash, $bytes, true));
    }

    /**
     * The text of the first descendant of the element with the local name.
     *
     * @param  \DOMElement  $element
     * @param  string  $name
     * @return string
     */
    private static function text(\DOMElement $element, string $name): string
    {
        return (string) $element->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', $name)->item(0)?->textContent;
    }

    /**
     * The local names of the element's child elements, in order.
     *
     * @param  \DOMElement  $element
     * @return list<string>
     */
    private static function childNames(\DOMElement $element): array
    {
        $names = [];

        foreach ($element->childNodes as $child) {
            if (!$child instanceof \DOMElement) {
                continue;
            }

            $names[] = (string) $child->localName;
        }

        return $names;
    }

    /**
     * The element's first child element with the local name.
     *
     * @param  \DOMElement  $element
     * @param  string  $name
     * @return \DOMElement
     */
    private static function childNamed(\DOMElement $element, string $name): \DOMElement
    {
        foreach ($element->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === $name) {
                return $child;
            }
        }

        self::fail(sprintf('The element has no %s.', $name));
    }

    /**
     * The certificate's base64 body.
     *
     * @return string
     */
    private static function certificateBody(): string
    {
        return (string) preg_replace('/-----[^-]+-----|\s+/', '', self::keys()[1]);
    }

    /**
     * A fresh copy of the document signed.
     *
     * @return \DOMDocument
     */
    private static function document(): \DOMDocument
    {
        $document = new \DOMDocument;

        $document->loadXML(self::DOCUMENT);

        return $document;
    }

    /**
     * The document's root.
     *
     * @param  \DOMDocument  $document
     * @return \DOMElement
     */
    private static function root(\DOMDocument $document): \DOMElement
    {
        return $document->documentElement ?? self::fail('The document has no root.');
    }

    /**
     * The signer, with the keys made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\XmlSigner
     */
    private static function signer(): XmlSigner
    {
        return new XmlSigner(...self::keys());
    }

    /**
     * The private key and certificate, made once.
     *
     * @return array{0: string, 1: string}
     */
    private static function keys(): array
    {
        return self::$keys ??= FakeSamlIdentityProvider::keyPair('signer.example.test');
    }
}
