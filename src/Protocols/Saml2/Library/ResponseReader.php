<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use SimpleSAML\SAML2\XML\samlp\Response;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlStatus;

/**
 * Reads one posted SAML `Response` in the fixed order of the agreed pipeline
 * (SSO-6.1 to SSO-6.3, SSO-6.7, SSO-6.8, SSO-6.11):
 *
 * 1. its parsed document must be a `samlp:Response` (the hardened parser has
 *    capped, parsed, schema-validated it and refused a repeated `ID`); every
 *    `ds:Signature` in it must be the response's own, as a child of the root,
 *    or its one assertion's own, as a child of
 *    `/samlp:Response/saml:Assertion`; and every `Assertion` or
 *    `EncryptedAssertion` anywhere in it must be a child of the root, at most
 *    one, so a wrapped, injected or second assertion is refused wherever it
 *    hides;
 * 2. the response's own signature, when present, is verified with a pinned
 *    verifier, and the response is read from the verified object from then on,
 *    with the element parsed from the bytes it digested kept for what the
 *    library does not model of an assertion it covers;
 * 3. its status decides the profile: an unsuccessful response reads no
 *    assertion, but a plain assertion's signature is still verified, since
 *    every signature present must verify;
 * 4. a successful response must carry exactly one assertion. A plain one that
 *    carries its own signature is copied into a document of its own (the
 *    re-rooting the v6 library needs, `docs/design/saml-library.md`) and
 *    verified; an encrypted one is decrypted (AES-CBC only after a verified
 *    response signature), and its plaintext parsed, schema-validated and held
 *    to the same structure and signature rules as a plain one;
 * 5. an assertion covered by no verified signature, its own or the response's,
 *    is refused; and one whose `ID` repeats the response's is refused. Every
 *    value of an assertion is read from what a verified signature covers: the
 *    library's verified object, and, for what it does not model, the element
 *    parsed from the bytes that signature digested (its own, or the verified
 *    response's child assertion), never the posted document; a decrypted
 *    assertion covered only by the response's signature is read from its
 *    plaintext, whose ciphertext that signature covers;
 * 6. a response with an `InResponseTo` anywhere, its decrypted assertion
 *    included, is `solicited`, and one with none `unsolicited`.
 *
 * Every refusal is a `ReadFailure` the adapter answers as a value. It holds the
 * parser, the verifier, the decryptor and the mapper, none of which keeps
 * anything between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResponseReader
{
    /** @var string The SAML protocol namespace. */
    public const string NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /** @var string The SAML assertion namespace. */
    public const string NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** @var string The XML signature namespace. */
    public const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /** @var string Every signature in the document. */
    private const string SIGNATURES = '//ds:Signature';

    /** @var string The signatures that may be in a response: its own and its one plain assertion's. */
    private const string ALLOWED_SIGNATURES = '/samlp:Response/ds:Signature | /samlp:Response/saml:Assertion/ds:Signature';

    /** @var string Every assertion, plain or encrypted, in the document. */
    private const string ASSERTIONS = '//saml:Assertion | //saml:EncryptedAssertion';

    /** @var string The assertions in their schema position, as children of the root. */
    private const string PLACED_ASSERTIONS = '/samlp:Response/saml:Assertion | /samlp:Response/saml:EncryptedAssertion';

    /** @var string The signatures that may be in a decrypted assertion: its own. */
    private const string DECRYPTED_SIGNATURES = '/saml:Assertion/ds:Signature';

    /** @var string Every `InResponseTo` attribute in a document. */
    private const string IN_RESPONSE_TO = '//@InResponseTo';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser  $parser
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\PinnedVerifier  $verifier
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\AssertionDecryptor  $decryptor
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\AssertionMapper  $mapper
     */
    public function __construct(

        /** Parses each document. */
        private HardenedParser $parser,

        /** Verifies each signature with the trusted certificates. */
        private PinnedVerifier $verifier,

        /** Decrypts an encrypted assertion. */
        private AssertionDecryptor $decryptor,

        /** Reads a verified assertion into the package's values. */
        private AssertionMapper $mapper,
    ) {}

    /**
     * The response the parsed document holds, every signature in it verified.
     *
     * @param  \DOMDocument  $document
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @param  int  $maxDecryptedBytes
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function read(\DOMDocument $document, ResponsePolicy $policy, int $maxDecryptedBytes): SamlResponse
    {
        self::assertStructure($document);

        $response = self::response($document);
        $signed   = $response->isSigned();
        $covered  = null;

        if ($signed) {
            [$response, $covered] = $this->verifier->verifiedElement($response, $policy->trustedCertificates, $policy->signatureAlgorithms);
        }

        $placed = self::placed($document);

        if (!$response->isSuccess()) {
            $this->verifyUnread($placed, $policy);

            return self::envelope($response, ValidationProfile::UNSUCCESSFUL, $signed, null);
        }

        [$assertion, $solicited] = $this->assertion($response, $placed, $policy, $covered, $maxDecryptedBytes);

        $profile = $solicited || self::inResponseTo($document) !== [] ? ValidationProfile::SOLICITED : ValidationProfile::UNSOLICITED;

        return self::envelope($response, $profile, $signed, $assertion);
    }

    /**
     * Every `InResponseTo` attribute in the document, in document order.
     *
     * @param  \DOMDocument  $document
     * @return list<string>
     */
    public static function inResponseTo(\DOMDocument $document): array
    {
        $values = [];

        foreach (self::nodes(self::xpath($document), self::IN_RESPONSE_TO) as $attribute) {
            $values[] = (string) $attribute->nodeValue;
        }

        return $values;
    }

    /**
     * Whether the document carries an `EncryptedAssertion` anywhere.
     *
     * @param  \DOMDocument  $document
     * @return bool
     */
    public static function isEncrypted(\DOMDocument $document): bool
    {
        return self::nodes(self::xpath($document), '//saml:EncryptedAssertion') !== [];
    }

    /**
     * Refuse a document that is not a response, or whose signatures or
     * assertions are anywhere but their schema position.
     *
     * @param  \DOMDocument  $document
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function assertStructure(\DOMDocument $document): void
    {
        $root = $document->documentElement;

        if ($root === null || $root->namespaceURI !== self::NS_SAMLP || $root->localName !== 'Response') {
            throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'not_a_response');
        }

        $xpath = self::xpath($document);

        if (!self::isWithin($xpath, self::SIGNATURES, self::ALLOWED_SIGNATURES)) {
            throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'signature_location');
        }

        $placed = count(self::nodes($xpath, self::PLACED_ASSERTIONS));

        if ($placed > 1 || !self::isWithin($xpath, self::ASSERTIONS, self::PLACED_ASSERTIONS)) {
            throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'assertion_location');
        }
    }

    /**
     * The library's response of the document.
     *
     * @param  \DOMDocument  $document
     * @return \SimpleSAML\SAML2\XML\samlp\Response
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     * @throws \LogicException
     */
    private static function response(\DOMDocument $document): Response
    {
        $root = $document->documentElement ?? throw new \LogicException('A parsed document has a root.');

        try {
            return Response::fromXML($root);
        } catch (\Throwable) {
            throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'structure');
        }
    }

    /**
     * The assertion or encrypted assertion in its schema position, as the
     * parsed document holds it, or `null` when there is none.
     *
     * @param  \DOMDocument  $document
     * @return ?\DOMElement
     */
    private static function placed(\DOMDocument $document): ?\DOMElement
    {
        $placed = self::nodes(self::xpath($document), self::PLACED_ASSERTIONS)[0] ?? null;

        return $placed instanceof \DOMElement ? $placed : null;
    }

    /**
     * Verify the signature of a plain assertion an unsuccessful response
     * carries, which it never reads.
     *
     * @param  ?\DOMElement  $placed
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private function verifyUnread(?\DOMElement $placed, ResponsePolicy $policy): void
    {
        if ($placed === null || $placed->localName !== 'Assertion') {
            return;
        }

        $assertion = self::reRooted($placed);

        if (!$assertion->isSigned()) {
            return;
        }

        $this->verifier->verified($assertion, $policy->trustedCertificates, $policy->signatureAlgorithms);
    }

    /**
     * The one assertion of a successful response, verified (and decrypted), and
     * whether its decrypted form carries an `InResponseTo`.
     *
     * @param  \SimpleSAML\SAML2\XML\samlp\Response  $response
     * @param  ?\DOMElement  $placed
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @param  ?\DOMElement  $covered
     * @param  int  $maxDecryptedBytes
     * @return array{0: \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion, 1: bool}
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private function assertion(Response $response, ?\DOMElement $placed, ResponsePolicy $policy, ?\DOMElement $covered, int $maxDecryptedBytes): array
    {
        $candidate = $response->getAssertions()[0] ?? null;

        if ($placed === null || $candidate === null) {
            throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'assertion_count');
        }

        if (!$candidate instanceof EncryptedAssertion) {
            return [$this->readAssertion($candidate, $placed, $response, $policy, [self::coveredAssertion($covered), false]), false];
        }

        $document = $this->decrypted($candidate, $policy, $covered !== null, $maxDecryptedBytes);
        $root     = $document->documentElement ?? throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'decrypted_structure');
        $verified = $this->readAssertion(self::reRooted($root), $root, $response, $policy, [$covered === null ? null : $root, true]);

        return [$verified, self::inResponseTo($document) !== []];
    }

    /**
     * The one assertion of the element parsed from the bytes the response's
     * signature digested, or `null` when no verified signature covers the
     * response.
     *
     * @param  ?\DOMElement  $covered
     * @return ?\DOMElement
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function coveredAssertion(?\DOMElement $covered): ?\DOMElement
    {
        if ($covered === null) {
            return null;
        }

        $document   = $covered->ownerDocument ?? throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'structure');
        $assertions = self::nodes(self::xpath($document), self::PLACED_ASSERTIONS);
        $assertion  = $assertions[0] ?? null;

        if (count($assertions) !== 1 || !$assertion instanceof \DOMElement) {
            throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'structure');
        }

        return $assertion;
    }

    /**
     * The decrypted assertion's document, parsed, schema-validated and held to
     * the structure of a plain one.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\EncryptedAssertion  $encrypted
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @param  bool  $signed
     * @param  int  $maxDecryptedBytes
     * @return \DOMDocument
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private function decrypted(EncryptedAssertion $encrypted, ResponsePolicy $policy, bool $signed, int $maxDecryptedBytes): \DOMDocument
    {
        $plaintext = $this->decryptor->decrypt($encrypted, $policy, $signed, $maxDecryptedBytes);
        $document  = $this->parser->parse($plaintext, MessageKind::ASSERTION, $maxDecryptedBytes);
        $root      = $document->documentElement;
        $xpath     = self::xpath($document);

        $isAssertion = $root !== null && $root->namespaceURI        === self::NS_SAML && $root->localName === 'Assertion';
        $isAlone     = count(self::nodes($xpath, self::ASSERTIONS)) === 1;

        if (!$isAssertion || !$isAlone || !self::isWithin($xpath, self::SIGNATURES, self::DECRYPTED_SIGNATURES)) {
            throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'decrypted_structure');
        }

        return $document;
    }

    /**
     * The assertion as the package's value, read from what a verified signature
     * covers: its own signature verified after re-rooting, or the verified
     * response's signature covering it, its decrypted form included; refused
     * when neither covers it, or its `ID` repeats the response's. What the
     * library does not model (other statements and conditions, `Advice`) is
     * read from the element parsed from the bytes its own signature digested,
     * or else from the element the response's signature covers.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\Assertion  $assertion
     * @param  \DOMElement  $element
     * @param  \SimpleSAML\SAML2\XML\samlp\Response  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @param  array{0: ?\DOMElement, 1: bool}  $provenance
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private function readAssertion(Assertion $assertion, \DOMElement $element, Response $response, ResponsePolicy $policy, array $provenance): SamlAssertion
    {
        [$covered, $encrypted] = $provenance;

        if ($assertion->getId()->getRawValue() === $response->getId()->getRawValue()) {
            throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'duplicate_id');
        }

        $own = $assertion->isSigned();

        if ($own) {
            [$assertion, $covered] = $this->verifier->verifiedElement(self::reRooted($element), $policy->trustedCertificates, $policy->signatureAlgorithms);
        }

        if ($covered === null) {
            throw new ReadFailure(FailureReason::SIGNATURE_INVALID, 'unsigned');
        }

        return $this->mapper->assertion($assertion, $covered, $own, $encrypted);
    }

    /**
     * The assertion element copied into a document of its own, so the library
     * digests the assertion rather than the response that held it (the v6
     * defect upstream PR #424 fixes), as the library's assertion.
     *
     * @param  \DOMElement  $element
     * @return \SimpleSAML\SAML2\XML\saml\Assertion
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function reRooted(\DOMElement $element): Assertion
    {
        try {
            $document = new \DOMDocument('1.0', 'UTF-8');
            $copy     = $document->importNode($element, true);

            $document->appendChild($copy);

            return Assertion::fromXML($copy instanceof \DOMElement ? $copy : throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'structure'));
        } catch (\Throwable) {
            throw new ReadFailure(FailureReason::RESPONSE_INVALID, 'structure');
        }
    }

    /**
     * The package's value of the response's envelope.
     *
     * @param  \SimpleSAML\SAML2\XML\samlp\Response  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile  $profile
     * @param  bool  $signed
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse
     */
    private static function envelope(Response $response, ValidationProfile $profile, bool $signed, ?SamlAssertion $assertion): SamlResponse
    {
        $status  = $response->getStatus();
        $code    = $status->getStatusCode();
        $issuer  = $response->getIssuer();
        $message = $status->getStatusMessage()?->getContent()->getRawValue();

        return new SamlResponse(
            $profile,
            $response->getId()->getRawValue(),
            AssertionMapper::instant($response->getIssueInstant()->toDateTime()),
            new SamlStatus($code->getValue()->getRawValue(), ($code->getSubCodes()[0] ?? null)?->getValue()->getRawValue(), $message),
            [
                'issuer'         => $issuer === null ? null : AssertionMapper::nameId($issuer),
                'destination'    => $response->getDestination()?->getRawValue(),
                'in_response_to' => $response->getInResponseTo()?->getRawValue(),
            ],
            $signed,
            $assertion,
        );
    }

    /**
     * Whether every node the query finds is one the allowed query finds.
     *
     * @param  \DOMXPath  $xpath
     * @param  string  $query
     * @param  string  $allowed
     * @return bool
     */
    private static function isWithin(\DOMXPath $xpath, string $query, string $allowed): bool
    {
        $permitted = [];

        foreach (self::nodes($xpath, $allowed) as $node) {
            $permitted[(string) $node->getNodePath()] = true;
        }

        foreach (self::nodes($xpath, $query) as $node) {
            if (!isset($permitted[(string) $node->getNodePath()])) {
                return false;
            }
        }

        return true;
    }

    /**
     * The nodes the query finds, in document order; none for a query that
     * fails.
     *
     * @param  \DOMXPath  $xpath
     * @param  string  $query
     * @return list<\DOMNode>
     */
    private static function nodes(\DOMXPath $xpath, string $query): array
    {
        $found = $xpath->query($query);

        return $found === false ? [] : array_values(array_filter(iterator_to_array($found), static fn ($node): bool => $node instanceof \DOMNode));
    }

    /**
     * An XPath over the document with the SAML and signature prefixes.
     *
     * @param  \DOMDocument  $document
     * @return \DOMXPath
     */
    private static function xpath(\DOMDocument $document): \DOMXPath
    {
        $xpath = new \DOMXPath($document);

        $xpath->registerNamespace('samlp', self::NS_SAMLP);
        $xpath->registerNamespace('saml', self::NS_SAML);
        $xpath->registerNamespace('ds', self::NS_DS);

        return $xpath;
    }
}
