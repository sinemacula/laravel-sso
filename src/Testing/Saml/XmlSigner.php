<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

/**
 * The enveloped XML signature the fake SAML identity provider signs its test
 * input with (SSO-12.4), seeded from the library spike's fixture generator.
 *
 * It is a minimal test tool that writes what a test needs, the hostile cases
 * included: exclusive canonicalisation with or without comments, RSA with
 * SHA-1, SHA-256, SHA-384 or SHA-512, a digest of any of those, a reference to
 * another element or to the whole document (`URI=""`), and a key and
 * certificate other than the provider's. The package never signs or verifies
 * with it: its own flows sign and verify only through its SAML adapter and the
 * maintained library behind it (SSO-6.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class XmlSigner
{
    /** @var array<string, string> The signature algorithms, by short name. */
    public const array SIGNATURE_ALGORITHMS = [
        'rsa-sha1'   => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        'rsa-sha256' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'rsa-sha384' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
        'rsa-sha512' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
    ];

    /** @var array<string, string> The digest algorithms, by short name. */
    public const array DIGEST_ALGORITHMS = [
        'sha1'   => 'http://www.w3.org/2000/09/xmldsig#sha1',
        'sha256' => 'http://www.w3.org/2001/04/xmlenc#sha256',
        'sha384' => 'http://www.w3.org/2001/04/xmldsig-more#sha384',
        'sha512' => 'http://www.w3.org/2001/04/xmlenc#sha512',
    ];

    /** @var array<string, int> The OpenSSL hash of each signature algorithm but SHA-256, by short name. */
    private const array HASHES = ['rsa-sha1' => OPENSSL_ALGO_SHA1, 'rsa-sha384' => OPENSSL_ALGO_SHA384, 'rsa-sha512' => OPENSSL_ALGO_SHA512];

    /** @var string The XML signature namespace. */
    private const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /** @var string Exclusive canonicalisation without comments. */
    private const string EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /** @var string Exclusive canonicalisation with comments. */
    private const string EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    /** @var string The enveloped-signature transform. */
    private const string ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /**
     * Constructor.
     *
     * @param  string  $privateKey
     * @param  string  $certificate
     */
    public function __construct(

        /** The PEM private key that signs. */
        #[\SensitiveParameter]
        private string $privateKey,

        /** The PEM certificate carried in the signature's `KeyInfo`. */
        private string $certificate,
    ) {}

    /**
     * Sign the element with an enveloped signature, placed after its `Issuer`
     * (or first, when it has none), and answer the signature element.
     *
     * Options: `algorithm` (`rsa-sha256` by default, a key of
     * `SIGNATURE_ALGORITHMS`), `digest` (`sha256`, a key of
     * `DIGEST_ALGORITHMS`), `comments` (canonicalise `SignedInfo` with
     * comments), `target` (the element the reference names and digests, the
     * element itself by default) and `uri` (the reference, `#` and the target's
     * `ID` by default; `''` digests the whole document).
     *
     * @param  \DOMElement  $element
     * @param  array{algorithm?: string, digest?: string, comments?: bool, target?: \DOMElement, uri?: string}  $options
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    public function sign(\DOMElement $element, array $options = []): \DOMElement
    {
        try {
            return $this->signed($element, $options);
        } catch (\DOMException $exception) {
            throw new \LogicException('The fake identity provider could not sign the element.', 0, $exception);
        }
    }

    /**
     * The RSA signature of the data with the algorithm, base64 encoded, as an
     * HTTP-Redirect query string or a signed `SignedInfo` carries it.
     *
     * @param  string  $data
     * @param  string  $algorithm
     * @return string
     *
     * @throws \LogicException
     */
    public function signatureValue(string $data, string $algorithm = 'rsa-sha256'): string
    {
        $hash = self::HASHES[$algorithm] ?? OPENSSL_ALGO_SHA256;

        if (!openssl_sign($data, $signature, $this->privateKey, $hash)) {
            throw new \LogicException('The fake identity provider could not sign.');
        }

        return base64_encode($signature);
    }

    /**
     * What `sign()` answers, a DOM failure let through.
     *
     * @param  \DOMElement  $element
     * @param  array{algorithm?: string, digest?: string, comments?: bool, target?: \DOMElement, uri?: string}  $options
     * @return \DOMElement
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private function signed(\DOMElement $element, array $options = []): \DOMElement
    {
        $document  = self::documentOf($element);
        $target    = $options['target']    ?? $element;
        $uri       = $options['uri']       ?? '#' . $target->getAttribute('ID');
        $digest    = $options['digest']    ?? 'sha256';
        $algorithm = $options['algorithm'] ?? 'rsa-sha256';
        $digested  = ($uri === '' ? $document : $target)->C14N(true, false);

        $signature = $document->createElementNS(self::NS_DS, 'ds:Signature');
        $info      = $this->signedInfo($document, $algorithm, $options['comments'] ?? false);

        $info->appendChild($this->reference($document, $uri, $digest, (string) $digested));
        $signature->appendChild($info);

        $value = $signature->appendChild($document->createElementNS(self::NS_DS, 'ds:SignatureValue'));

        $signature->appendChild($this->keyInfo($document));
        $element->insertBefore($signature, self::anchor($element));

        // The SignedInfo holds no comment, so it canonicalises the same with or
        // without them
        $value->appendChild($document->createTextNode($this->signatureValue((string) $info->C14N(true), $algorithm)));

        return $signature;
    }

    /**
     * The `SignedInfo`, with its canonicalisation and signature method.
     *
     * @param  \DOMDocument  $document
     * @param  string  $algorithm
     * @param  bool  $comments
     * @return \DOMElement
     *
     * @throws \DOMException
     */
    private function signedInfo(\DOMDocument $document, string $algorithm, bool $comments): \DOMElement
    {
        $info = $document->createElementNS(self::NS_DS, 'ds:SignedInfo');

        $info->appendChild($document->createElementNS(self::NS_DS, 'ds:CanonicalizationMethod'))->setAttribute('Algorithm', $comments ? self::EXC_C14N_COMMENTS : self::EXC_C14N);
        $info->appendChild($document->createElementNS(self::NS_DS, 'ds:SignatureMethod'))->setAttribute('Algorithm', self::SIGNATURE_ALGORITHMS[$algorithm]);

        return $info;
    }

    /**
     * The `Reference`, with the enveloped and exclusive canonicalisation
     * transforms and the digest of the canonical bytes.
     *
     * @param  \DOMDocument  $document
     * @param  string  $uri
     * @param  string  $digest
     * @param  string  $digested
     * @return \DOMElement
     *
     * @throws \DOMException
     */
    private function reference(\DOMDocument $document, string $uri, string $digest, string $digested): \DOMElement
    {
        $reference  = $document->createElementNS(self::NS_DS, 'ds:Reference');
        $transforms = $reference->appendChild($document->createElementNS(self::NS_DS, 'ds:Transforms'));

        $reference->setAttribute('URI', $uri);
        $transforms->appendChild($document->createElementNS(self::NS_DS, 'ds:Transform'))->setAttribute('Algorithm', self::ENVELOPED);
        $transforms->appendChild($document->createElementNS(self::NS_DS, 'ds:Transform'))->setAttribute('Algorithm', self::EXC_C14N);
        $reference->appendChild($document->createElementNS(self::NS_DS, 'ds:DigestMethod'))->setAttribute('Algorithm', self::DIGEST_ALGORITHMS[$digest]);
        $reference->appendChild($document->createElementNS(self::NS_DS, 'ds:DigestValue', base64_encode(hash($digest, $digested, true))));

        return $reference;
    }

    /**
     * The `KeyInfo` carrying the certificate.
     *
     * @param  \DOMDocument  $document
     * @return \DOMElement
     *
     * @throws \DOMException
     */
    private function keyInfo(\DOMDocument $document): \DOMElement
    {
        $keyInfo = $document->createElementNS(self::NS_DS, 'ds:KeyInfo');
        $data    = $keyInfo->appendChild($document->createElementNS(self::NS_DS, 'ds:X509Data'));
        $body    = (string) preg_replace('/-----[^-]+-----|\s+/', '', $this->certificate);

        $data->appendChild($document->createElementNS(self::NS_DS, 'ds:X509Certificate', $body));

        return $keyInfo;
    }

    /**
     * The document the element belongs to.
     *
     * @param  \DOMElement  $element
     * @return \DOMDocument
     *
     * @throws \LogicException
     */
    private static function documentOf(\DOMElement $element): \DOMDocument
    {
        return $element->ownerDocument ?? throw new \LogicException('The element to sign belongs to a document.');
    }

    /**
     * The child the signature goes before: the one after the element's
     * `Issuer`, or its first child when it has none.
     *
     * @param  \DOMElement  $element
     * @return ?\DOMNode
     */
    private static function anchor(\DOMElement $element): ?\DOMNode
    {
        foreach ($element->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === 'Issuer') {
                return $child->nextSibling;
            }
        }

        return $element->firstChild;
    }
}
