<?php

declare(strict_types = 1);

namespace Tests\Concerns;

/**
 * Outlines a SAML document as the elements a signature wrapping moves: every
 * `Response`, `Assertion`, `EncryptedAssertion`, `Signature`, `Extensions` and
 * `Object`, each with its `ID` and the outlined elements inside it, in document
 * order. `Response#_r{Signature,Assertion#_a}` is a response whose signature
 * precedes its assertion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait OutlinesSamlDocuments
{
    /** @var list<string> The local names an outline shows. */
    private const array OUTLINED = ['Response', 'Assertion', 'EncryptedAssertion', 'Signature', 'Extensions', 'Object'];

    /**
     * The outline of the XML's root.
     *
     * @param  string  $xml
     * @return string
     */
    protected static function outline(string $xml): string
    {
        $document = new \DOMDocument;

        self::assertTrue($document->loadXML($xml));

        return self::outlineOf($document->documentElement ?? self::fail('The document has no root.'));
    }

    /**
     * The outline of the element.
     *
     * @param  \DOMElement  $element
     * @return string
     */
    private static function outlineOf(\DOMElement $element): string
    {
        $children = [];

        foreach ($element->childNodes as $child) {
            if (!$child instanceof \DOMElement || !in_array($child->localName, self::OUTLINED, true)) {
                continue;
            }

            $children[] = self::outlineOf($child);
        }

        $id = $element->getAttribute('ID');

        return $element->localName . ($id === '' ? '' : '#' . $id) . ($children === [] ? '' : '{' . implode(',', $children) . '}');
    }
}
