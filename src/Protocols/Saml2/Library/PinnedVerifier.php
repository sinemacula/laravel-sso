<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\SAML2\XML\md\AbstractSignedMdElement;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\samlp\AbstractMessage;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\Reference;
use SimpleSAML\XMLSecurity\XML\ds\SignedInfo;
use SimpleSAML\XMLSecurity\XML\SignedElementInterface;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * Verifies a signed element only against certificates the connection trusts;
 * `KeyInfo` in the message is never read. Values are read only from what the
 * library rebuilt from the digested bytes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PinnedVerifier
{
    /** @var list<string> The signature algorithms the library verifies. */
    public const array SIGNATURE_ALGORITHMS = [C::SIG_RSA_SHA256, C::SIG_RSA_SHA384, C::SIG_RSA_SHA512];

    /** @var list<string> The digest algorithms a reference may use: never SHA-1. */
    public const array DIGEST_ALGORITHMS = [C::DIGEST_SHA256, C::DIGEST_SHA384, C::DIGEST_SHA512];

    /** @var list<string> The transforms a reference may list, each at most once. */
    public const array TRANSFORMS = [C::XMLDSIG_ENVELOPED, C::C14N_EXCLUSIVE_WITHOUT_COMMENTS];

    /** @var string The one canonicalisation a `SignedInfo` may use. */
    public const string CANONICALIZATION = C::C14N_EXCLUSIVE_WITHOUT_COMMENTS;

    /**
     * The element rebuilt from the digested bytes, once its signature meets the
     * policy and a trusted certificate verifies it.
     *
     * @template TElement of \SimpleSAML\XMLSecurity\XML\SignedElementInterface
     *
     * @param  TElement  $element
     * @param  list<string>  $certificates
     * @param  list<string>  $algorithms
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return TElement
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function verified(
        SignedElementInterface $element,
        array $certificates,
        array $algorithms,
        FailureReason $reason = FailureReason::SIGNATURE_INVALID,
    ): SignedElementInterface {
        $algorithm = self::admittedAlgorithm($element, $algorithms, $reason);

        foreach ($certificates as $certificate) {

            $verified = self::attempt($element, $algorithm, $certificate);

            if ($verified !== null) {
                return $verified;
            }
        }

        throw new ReadFailure($reason, 'signature');
    }

    /**
     * The verified element, with the digested bytes parsed into a document of
     * their own for what the library does not model.
     *
     * @template TElement of \SimpleSAML\XMLSecurity\XML\SignedElementInterface
     *
     * @param  TElement  $element
     * @param  list<string>  $certificates
     * @param  list<string>  $algorithms
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return array{0: TElement, 1: \DOMElement}
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function verifiedElement(SignedElementInterface $element, array $certificates, array $algorithms, FailureReason $reason = FailureReason::SIGNATURE_INVALID): array
    {
        $verified = $this->verified($element, $certificates, $algorithms, $reason);

        try {
            $digested = self::digested($element);
        } catch (\Throwable) {
            throw new ReadFailure($reason, 'signature');
        }

        return [$verified, $digested];
    }

    /**
     * The bytes the library digested, made as it makes them, parsed afresh so
     * no later change to the source document reaches them.
     *
     * @param  \SimpleSAML\XMLSecurity\XML\SignedElementInterface  $element
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    private static function digested(SignedElementInterface $element): \DOMElement
    {
        $signed     = self::keepingItsXml($element);
        $transforms = $signed->getSignature()?->getSignedInfo()->getReferences()[0]->getTransforms();

        try {
            $root = self::unsignedRoot($signed->getXML());
        } catch (\DOMException) {
            $root = null;
        }

        if ($transforms === null || $root === null) {
            throw new \LogicException('A verified element is digested through its reference\'s transforms.');
        }

        return DOMDocumentFactory::fromString($signed->processTransforms($transforms, $root))->documentElement
            ?? throw new \LogicException('Digested bytes hold an element.');
    }

    /**
     * The source document's root, copied without its own signature as the
     * library copies it to digest; `null` when it cannot be copied.
     *
     * @param  \DOMElement  $original
     * @return ?\DOMElement
     *
     * @throws \DOMException
     */
    private static function unsignedRoot(\DOMElement $original): ?\DOMElement
    {
        $document = DOMDocumentFactory::create();
        $root     = $document->importNode($original->ownerDocument->documentElement ?? $original, true);

        if (!$root instanceof \DOMElement) {
            return null;
        }

        $document->appendChild($root);

        foreach (array_filter(iterator_to_array($root->childNodes), static fn (\DOMNode $node): bool => self::isSignature($node)) as $signature) {
            $root->removeChild($signature);
        }

        return $root;
    }

    /**
     * Whether the node is a `ds:Signature` element.
     *
     * @param  \DOMNode  $node
     * @return bool
     */
    private static function isSignature(\DOMNode $node): bool
    {
        return $node instanceof \DOMElement && $node->namespaceURI === C::NS_XDSIG && $node->localName === 'Signature';
    }

    /**
     * The element narrowed to a signed element type that keeps its source XML.
     *
     * @param  \SimpleSAML\XMLSecurity\XML\SignedElementInterface  $element
     * @return \SimpleSAML\SAML2\XML\md\AbstractSignedMdElement|\SimpleSAML\SAML2\XML\saml\Assertion|\SimpleSAML\SAML2\XML\samlp\AbstractMessage
     *
     * @throws \LogicException
     */
    private static function keepingItsXml(SignedElementInterface $element): AbstractMessage|AbstractSignedMdElement|Assertion
    {
        return match (true) {
            $element instanceof Assertion               => $element,
            $element instanceof AbstractMessage         => $element,
            $element instanceof AbstractSignedMdElement => $element,
            default                                     => throw new \LogicException(sprintf('A %s keeps no XML to read from.', $element::class)),
        };
    }

    /**
     * The element verified with the certificate, or `null`.
     *
     * @template TElement of \SimpleSAML\XMLSecurity\XML\SignedElementInterface
     *
     * @param  TElement  $element
     * @param  string  $algorithm
     * @param  string  $certificate
     * @return ?TElement
     */
    private static function attempt(SignedElementInterface $element, string $algorithm, string $certificate): ?SignedElementInterface
    {
        try {
            $key      = (new X509Certificate(PEM::fromString($certificate)))->getPublicKey();
            $verified = $element->verify((new SignatureAlgorithmFactory)->getAlgorithm($algorithm, $key));
        } catch (\Throwable) {
            return null;
        }

        return $verified instanceof $element ? $verified : null;
    }

    /**
     * The signature algorithm, once the `SignedInfo` meets the policy: allowed
     * method, exclusive c14n, one own-`ID` reference and no `Object`.
     *
     * @param  \SimpleSAML\XMLSecurity\XML\SignedElementInterface  $element
     * @param  list<string>  $algorithms
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return string
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function admittedAlgorithm(SignedElementInterface $element, array $algorithms, FailureReason $reason): string
    {
        $signature = $element->getSignature() ?? throw new ReadFailure($reason, 'signature_missing');
        $info      = $signature->getSignedInfo();
        $algorithm = $info->getSignatureMethod()->getAlgorithm()->getValue();
        $id        = $element->getId()?->getValue();

        $admitted = self::isAllowedMethod($info, $algorithm, $algorithms)
            && $signature->getObjects()                                       === []
            && $info->getCanonicalizationMethod()->getAlgorithm()->getValue() === self::CANONICALIZATION
            && self::isOwnReference($info, $id);

        if (!$admitted) {
            throw new ReadFailure($reason, 'signature_policy');
        }

        return $algorithm;
    }

    /**
     * Whether the method is allowed and verifiable, with no HMAC output length.
     *
     * @param  \SimpleSAML\XMLSecurity\XML\ds\SignedInfo  $info
     * @param  string  $algorithm
     * @param  list<string>  $algorithms
     * @return bool
     */
    private static function isAllowedMethod(SignedInfo $info, string $algorithm, array $algorithms): bool
    {
        $allowed = in_array($algorithm, $algorithms, true) && in_array($algorithm, self::SIGNATURE_ALGORITHMS, true);

        return $allowed && $info->getSignatureMethod()->getHMACOutputLength() === null;
    }

    /**
     * Whether there is exactly one reference, to the element's own id, with an
     * allowed digest and only allowed transforms.
     *
     * @param  \SimpleSAML\XMLSecurity\XML\ds\SignedInfo  $info
     * @param  ?string  $id
     * @return bool
     */
    private static function isOwnReference(SignedInfo $info, ?string $id): bool
    {
        $references = $info->getReferences();

        if ($id === null || count($references) !== 1) {
            return false;
        }

        $reference = $references[0];
        $digest    = $reference->getDigestMethod()->getAlgorithm()->getValue();

        return $reference->getURI()?->getValue() === '#' . $id
            && in_array($digest, self::DIGEST_ALGORITHMS, true)
            && self::hasAllowedTransforms($reference);
    }

    /**
     * Whether the reference lists only allowed transforms, each at most once.
     *
     * @param  \SimpleSAML\XMLSecurity\XML\ds\Reference  $reference
     * @return bool
     */
    private static function hasAllowedTransforms(Reference $reference): bool
    {
        $algorithms = array_map(
            static fn ($transform): string => $transform->getAlgorithm()->getValue(),
            $reference->getTransforms()?->getTransform() ?? [],
        );

        return array_diff($algorithms, self::TRANSFORMS) === [] && count($algorithms) === count(array_unique($algorithms));
    }
}
