<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

/**
 * Reads the XML the fake SAML helpers are given (SSO-12.4): an `AuthnRequest`
 * the package sent, or the service provider metadata it describes. The package
 * wrote both, so this reads them plainly, never as the package's hardened
 * parser reads what an identity provider sends: no network, no document type,
 * and every libxml warning kept from the test.
 *
 * Anything it cannot read is a `LogicException` naming what was expected, so a
 * test fails where the message went wrong.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class XmlDocument
{
    /**
     * The root element of the document, named in a failure as what it was meant
     * to be.
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
     * The value of the element's attribute, which must not be empty.
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
     * The trimmed text of the first element of the namespace and name inside
     * the element, which must not be empty.
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
