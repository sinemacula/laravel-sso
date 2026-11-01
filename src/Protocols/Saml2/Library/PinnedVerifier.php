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
 * Verifies one signed element of a SAML document, only ever with a verifier
 * built from a certificate the connection trusts (SSO-2.6, SSO-6.2, SSO-6.3,
 * SSO-6.7): the library's `verify()` is never called without one, so a
 * certificate or key carried in the message's `KeyInfo` is never trusted for
 * itself and never even read.
 *
 * Before anything is verified, the parsed `SignedInfo` is held to the package's
 * policy, which the signature covers: the `SignatureMethod` is one the
 * connection allows and the library verifies (RSA with SHA-256, SHA-384 or
 * SHA-512), with no HMAC output length; the `CanonicalizationMethod` is
 * exclusive canonicalisation without comments; there is exactly one
 * `Reference`, a same-document `#ID` naming the element itself, compared
 * exactly; its `DigestMethod` is SHA-256, SHA-384 or SHA-512, never SHA-1; its
 * transforms are only the enveloped-signature and exclusive canonicalisation
 * transforms, each at most once; and the signature carries no `Object`.
 *
 * The element is then verified with each trusted certificate in turn, the first
 * that verifies it giving the element the library rebuilt from the bytes that
 * were digested, which is the only object any value is read from. What the
 * library does not model is read from the DOM element `verifiedElement()`
 * answers with it: those same digested bytes, made exactly as the library made
 * them (the signed document's root copied, its own `ds:Signature` removed, the
 * reference's transforms applied) and parsed into a document of their own, so
 * no later change to the document the element came from can reach it. A policy
 * refusal, or no certificate verifying, is a `ReadFailure` with the reason
 * given (`signature_invalid` by default); the element is never answered
 * unverified. It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PinnedVerifier
{
    /** @var list<string> The signature algorithms the library verifies, so the most a connection may allow. */
    public const array SIGNATURE_ALGORITHMS = [C::SIG_RSA_SHA256, C::SIG_RSA_SHA384, C::SIG_RSA_SHA512];

    /** @var list<string> The digest algorithms a reference may use: never SHA-1. */
    public const array DIGEST_ALGORITHMS = [C::DIGEST_SHA256, C::DIGEST_SHA384, C::DIGEST_SHA512];

    /** @var list<string> The transforms a reference may list, each at most once. */
    public const array TRANSFORMS = [C::XMLDSIG_ENVELOPED, C::C14N_EXCLUSIVE_WITHOUT_COMMENTS];

    /** @var string The one canonicalisation a `SignedInfo` may use. */
    public const string CANONICALIZATION = C::C14N_EXCLUSIVE_WITHOUT_COMMENTS;

    /**
     * The element as the library rebuilt it from the digested bytes, once its
     * signature meets the policy and a trusted certificate verifies it.
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
     * The element as the library rebuilt it from the digested bytes, with those
     * bytes parsed as a DOM element of a document of their own, once its
     * signature meets the policy and a trusted certificate verifies it.
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
     * The bytes the library digested to verify the element, made as it makes
     * them, parsed as the root of a document of their own.
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
     * The root of the document the element was read from, copied into a
     * document of its own without its own signature, as the library copies it
     * to digest it; `null` when it cannot be copied.
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
     * The element, as one of the library's signed elements that keep the XML
     * they were read from: an assertion, a protocol message or a metadata
     * descriptor.
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
     * The element verified with the certificate, or `null` when it does not
     * verify it or cannot be read.
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
     * The signature algorithm, once the element's signature meets the policy.
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
     * Whether the signature method is allowed by the connection and verified by
     * the library, with no HMAC output length.
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
     * Whether the signature has exactly one reference, to the element's own id,
     * with an allowed digest and only allowed transforms.
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
