<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XML\DOMDocumentFactory;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;

/**
 * The size-capped, DTD-free, schema-validated parsing every SAML document goes
 * through, with no `ID` repeated and no network access.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HardenedParser
{
    /** @var string `ID`, `Id`, `id` and `xml:id` attributes, as an XPath union. */
    private const string ID_ATTRIBUTES = '//@ID | //@Id | //@id | //@*[local-name() = "id" and namespace-uri() = "http://www.w3.org/XML/1998/namespace"]';

    /**
     * Decode a posted base64 value, capped before decoding.
     *
     * @param  string  $encoded
     * @param  int  $maxBytes
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return string
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function decode(#[\SensitiveParameter] string $encoded, int $maxBytes, FailureReason $reason = FailureReason::RESPONSE_INVALID): string
    {
        if (strlen($encoded) > $maxBytes) {
            throw new ReadFailure($reason, 'too_large');
        }

        $decoded = base64_decode($encoded, true);

        if ($decoded === false || $decoded === '') {
            throw new ReadFailure($reason, 'not_base64');
        }

        return $decoded;
    }

    /**
     * Parse a capped document, valid against its schema, with no `ID` repeated.
     *
     * @param  string  $xml
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind  $kind
     * @param  int  $maxBytes
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \DOMDocument
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function parse(#[\SensitiveParameter] string $xml, MessageKind $kind, int $maxBytes, FailureReason $reason = FailureReason::RESPONSE_INVALID): \DOMDocument
    {
        $document = $this->load($xml, $maxBytes, $reason);

        self::validate($document, $kind, $reason);
        self::assertUniqueIds($document, $reason);

        return $document;
    }

    /**
     * Parse a capped document with no `ID` repeated, leaving the schema to
     * `validateElement()` so one invalid federation member spoils no other.
     *
     * @param  string  $xml
     * @param  int  $maxBytes
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \DOMDocument
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function loadUnique(#[\SensitiveParameter] string $xml, int $maxBytes, FailureReason $reason = FailureReason::RESPONSE_INVALID): \DOMDocument
    {
        $document = $this->load($xml, $maxBytes, $reason);

        self::assertUniqueIds($document, $reason);

        return $document;
    }

    /**
     * Validate one element against its schema, re-rooted with its in-scope
     * namespaces so a prefix in an attribute value still resolves.
     *
     * @param  \DOMElement  $element
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind  $kind
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function validateElement(\DOMElement $element, MessageKind $kind, FailureReason $reason = FailureReason::RESPONSE_INVALID): void
    {
        self::validate(self::reRooted($element, $reason), $kind, $reason);
    }

    /**
     * Parse a capped document without schema validation. The factory refuses
     * any DTD and parses with `LIBXML_NONET`.
     *
     * @param  string  $xml
     * @param  int  $maxBytes
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \DOMDocument
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function load(#[\SensitiveParameter] string $xml, int $maxBytes, FailureReason $reason = FailureReason::RESPONSE_INVALID): \DOMDocument
    {
        if (strlen($xml) > $maxBytes) {
            throw new ReadFailure($reason, 'too_large');
        }

        LibraryContainer::ensure();

        try {
            return DOMDocumentFactory::fromString($xml);
        } catch (\Throwable) { // @phpstan-ignore catch.neverThrown (the factory throws on any XML it refuses, undeclared)
            throw new ReadFailure($reason, 'unparseable');
        }
    }

    /**
     * The absolute path of the library's schema of the kind.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind  $kind
     * @return string
     */
    public static function schemaPath(MessageKind $kind): string
    {
        return self::schemaDirectory() . DIRECTORY_SEPARATOR . $kind->schema();
    }

    /**
     * The real path of a resource inside the library's schema directory, or
     * `null`, so validation reaches no network.
     *
     * @param  ?string  $system
     * @return ?string
     */
    public static function localSchema(?string $system): ?string
    {
        $path = $system === null ? false : realpath($system);

        if ($path === false || !str_starts_with($path, self::schemaDirectory() . DIRECTORY_SEPARATOR)) {
            return null;
        }

        return $path;
    }

    /**
     * Validate against the schema, restoring libxml state however it ends.
     *
     * @param  \DOMDocument  $document
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind  $kind
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function validate(\DOMDocument $document, MessageKind $kind, FailureReason $reason): void
    {
        $errors = libxml_use_internal_errors(true);

        libxml_set_external_entity_loader(static fn (?string $public, ?string $system): ?string => self::localSchema($system));

        try {
            Response::schemaValidate($document, self::schemaPath($kind));
        } catch (\Throwable) {
            throw new ReadFailure($reason, 'schema');
        } finally {
            libxml_set_external_entity_loader(null);
            libxml_clear_errors();
            libxml_use_internal_errors($errors);
        }
    }

    /**
     * The element copied into its own document with its in-scope namespaces.
     *
     * @param  \DOMElement  $element
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \DOMDocument
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function reRooted(\DOMElement $element, FailureReason $reason): \DOMDocument
    {
        $document = new \DOMDocument('1.0', 'UTF-8');
        $scope    = $element->ownerDocument === null ? false : (new \DOMXPath($element->ownerDocument))->query('namespace::*', $element);

        try {
            $copy = $document->importNode($element, true);

            if (!$copy instanceof \DOMElement || $scope === false) {
                throw new ReadFailure($reason, 'structure');
            }

            $document->appendChild($copy);

            foreach ($scope as $namespace) {
                self::declare($copy, $namespace);
            }
        } catch (\DOMException) {
            throw new ReadFailure($reason, 'structure');
        }

        return $document;
    }

    /**
     * Declare the namespace on the copy unless it is `xml` or already bound.
     *
     * @param  \DOMElement  $copy
     * @param  \DOMNameSpaceNode|\DOMNode  $namespace
     * @return void
     *
     * @throws \DOMException
     */
    private static function declare(\DOMElement $copy, \DOMNameSpaceNode|\DOMNode $namespace): void
    {
        $prefix = $namespace instanceof \DOMNameSpaceNode ? $namespace->prefix : 'xml';

        if ($prefix === 'xml' || $copy->lookupNamespaceURI($prefix === '' ? null : $prefix) !== null) {
            return;
        }

        $copy->setAttributeNS('http://www.w3.org/2000/xmlns/', $namespace->nodeName, (string) $namespace->nodeValue);
    }

    /**
     * Refuse a document in which two identity attributes share a value.
     *
     * @param  \DOMDocument  $document
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function assertUniqueIds(\DOMDocument $document, FailureReason $reason): void
    {
        $seen = [];

        foreach ((new \DOMXPath($document))->query(self::ID_ATTRIBUTES) ?: [] as $attribute) {

            $value = (string) $attribute->nodeValue;

            if (isset($seen[$value])) {
                throw new ReadFailure($reason, 'duplicate_id');
            }

            $seen[$value] = true;
        }
    }

    /**
     * The real path of the library's schema directory.
     *
     * @return string
     */
    private static function schemaDirectory(): string
    {
        $directory = dirname((string) (new \ReflectionClass(Response::class))->getFileName(), 4) . '/resources/schemas';

        return (string) realpath($directory);
    }
}
