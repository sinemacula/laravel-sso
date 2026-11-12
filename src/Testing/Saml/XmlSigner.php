<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

/**
 * A minimal enveloped XML signer for the fake identity provider, able to write
 * hostile signatures. The package's own flows never use it.
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

    /** @var array<string, string> The transforms a reference may list, by short name. */
    public const array TRANSFORMS = [
        'enveloped'         => self::ENVELOPED,
        'exc-c14n'          => self::EXC_C14N,
        'exc-c14n-comments' => self::EXC_C14N_COMMENTS,
    ];

    /** @var array<string, int> OpenSSL hashes by algorithm; SHA-256 is the fallback. */
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
     * Sign the element after its `Issuer` and return the signature. The digest
     * is always exclusive c14n without comments, whatever the transforms say.
     *
     * @param  \DOMElement  $element
     * @param  array{algorithm?: string, digest?: string, comments?: bool, target?: \DOMElement, uri?: string, transforms?: list<string>}  $options
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
     * The base64 RSA signature of the data.
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
     * The signature `sign()` returns, letting a DOM failure through.
     *
     * @param  \DOMElement  $element
     * @param  array{algorithm?: string, digest?: string, comments?: bool, target?: \DOMElement, uri?: string, transforms?: list<string>}  $options
     * @return \DOMElement
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private function signed(\DOMElement $element, array $options = []): \DOMElement
    {
        $document  = $element->ownerDocument ?? throw new \LogicException('The element to sign belongs to a document.');
        $target    = $options['target']      ?? $element;
        $uri       = $options['uri']         ?? '#' . $target->getAttribute('ID');
        $digest    = $options['digest']      ?? 'sha256';
        $algorithm = $options['algorithm']   ?? 'rsa-sha256';
        $digested  = ($uri === '' ? $document : $target)->C14N(true, false);

        $signature = $document->createElementNS(self::NS_DS, 'ds:Signature');
        $info      = $this->signedInfo($document, $algorithm, $options['comments'] ?? false);

        $info->appendChild($this->reference($document, [$uri, $digest, (string) $digested], $options['transforms'] ?? ['enveloped', 'exc-c14n']));
        $signature->appendChild($info);

        $value = $signature->appendChild($document->createElementNS(self::NS_DS, 'ds:SignatureValue'));

        $signature->appendChild($this->keyInfo($document));
        $element->insertBefore($signature, self::anchor($element));

        // SignedInfo holds no comment, so either canonicalisation is the same
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
     * The `Reference` to the URI, with its transforms and digest.
     *
     * @param  \DOMDocument  $document
     * @param  array{0: string, 1: string, 2: string}  $digest
     * @param  list<string>  $names
     * @return \DOMElement
     *
     * @throws \DOMException
     */
    private function reference(\DOMDocument $document, array $digest, array $names): \DOMElement
    {
        [$uri, $algorithm, $digested] = $digest;

        $reference  = $document->createElementNS(self::NS_DS, 'ds:Reference');
        $transforms = $reference->appendChild($document->createElementNS(self::NS_DS, 'ds:Transforms'));

        $reference->setAttribute('URI', $uri);

        foreach ($names as $name) {
            $transforms->appendChild($document->createElementNS(self::NS_DS, 'ds:Transform'))->setAttribute('Algorithm', self::TRANSFORMS[$name]);
        }

        $reference->appendChild($document->createElementNS(self::NS_DS, 'ds:DigestMethod'))->setAttribute('Algorithm', self::DIGEST_ALGORITHMS[$algorithm]);
        $reference->appendChild($document->createElementNS(self::NS_DS, 'ds:DigestValue', base64_encode(hash($algorithm, $digested, true))));

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
     * The child the signature goes before: the one after `Issuer`, else the
     * first.
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
