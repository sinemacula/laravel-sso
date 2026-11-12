<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

/**
 * Reads XML the package wrote for the fake SAML helpers: plainly, with no
 * network, no document type and libxml warnings kept from the test.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class XmlDocument
{
    /**
     * The document's root element; a failure names what it was meant to be.
     *
     * @param  string  $xml
     * @param  string  $what
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    public static function root(string $xml, string $what): \DOMElement
    {
        $document = new \DOMDocument;
        $errors   = libxml_use_internal_errors(true);

        try {
            $loaded = $xml !== '' && $document->loadXML($xml, LIBXML_NONET);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($errors);
        }

        $root = $loaded && $document->doctype === null ? $document->documentElement : null;

        return $root ?? throw new \LogicException(sprintf('The %s is not an XML document without a document type.', $what));
    }

    /**
     * The element's non-empty attribute value.
     *
     * @param  \DOMElement  $element
     * @param  string  $name
     * @return string
     *
     * @throws \LogicException
     */
    public static function attribute(\DOMElement $element, string $name): string
    {
        $value = $element->getAttribute($name);

        return $value !== '' ? $value : throw new \LogicException(sprintf('The %s has no %s.', $element->localName, $name));
    }

    /**
     * The trimmed, non-empty text of the first descendant of the name.
     *
     * @param  \DOMElement  $element
     * @param  string  $namespace
     * @param  string  $name
     * @return string
     *
     * @throws \LogicException
     */
    public static function text(\DOMElement $element, string $namespace, string $name): string
    {
        $text = trim((string) $element->getElementsByTagNameNS($namespace, $name)->item(0)?->textContent);

        return $text !== '' ? $text : throw new \LogicException(sprintf('The %s has no %s.', $element->localName, $name));
    }
}
