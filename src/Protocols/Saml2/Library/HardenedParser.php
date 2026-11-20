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
    /** @var string The start of an element libxml serialised: its name, then its declarations and attributes. */
    private const string START_TAG = '/\A(<[^\s\/>]++)((?: [^\s=]++=(?:"[^"]*+"|\'[^\']*+\'))*+)(?=\/?>)/';

    /** @var string One declaration or attribute of a start tag, by name. */
    private const string ATTRIBUTE = '/ ([^\s=]++)=(?:"[^"]*+"|\'[^\']*+\')/';

    /** @var string The exclusive canonicalisation namespace, whose `InclusiveNamespaces` lists prefixes. */
    private const string NS_EC = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /** @var string The XML Schema instance namespace, whose `type` names a type by prefix. */
    private const string NS_XSI = 'http://www.w3.org/2001/XMLSchema-instance';

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
     * namespaces so a prefix in an attribute value still resolves, without the
     * children of its own namespace named in `$without`.
     *
     * @param  \DOMElement  $element
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind  $kind
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  list<string>  $without
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public function validateElement(\DOMElement $element, MessageKind $kind, FailureReason $reason = FailureReason::RESPONSE_INVALID, array $without = []): void
    {
        self::validate(self::pruned($element, $reason, $without), $kind, $reason);
    }

    /**
     * The element re-parsed into a document of its own with the inherited
     * declarations it relies on, so it canonicalises and digests as it did in
     * place.
     *
     * @param  \DOMElement  $element
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \DOMElement
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    public static function reRooted(\DOMElement $element, FailureReason $reason = FailureReason::RESPONSE_INVALID): \DOMElement
    {
        try {
            $document = $element->ownerDocument ?? throw new ReadFailure($reason, 'structure');

            // Serialised in place, every nested declaration stays where it is; importNode would re-prefix them
            $xml = (string) $document->saveXML($element);

            preg_match(self::START_TAG, $xml, $start) === 1 || throw new ReadFailure($reason, 'structure');

            [$first, $rest] = self::inherited($element, $start[2]);

            return DOMDocumentFactory::fromString($start[1] . $first . $start[2] . $rest . substr($xml, strlen($start[0])))->documentElement
                ?? throw new ReadFailure($reason, 'structure');
        } catch (\Throwable) {
            throw new ReadFailure($reason, 'structure');
        }
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
     * The element's own document, re-rooted, without the named children of its
     * own namespace.
     *
     * @param  \DOMElement  $element
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  list<string>  $without
     * @return \DOMDocument
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function pruned(\DOMElement $element, FailureReason $reason, array $without): \DOMDocument
    {
        $copy = self::reRooted($element, $reason);

        foreach (iterator_to_array($copy->childNodes) as $child) {
            if ($child->namespaceURI !== $copy->namespaceURI || !in_array($child->localName, $without, true)) {
                continue;
            }

            $copy->removeChild($child);
        }

        return $copy->ownerDocument ?? throw new ReadFailure($reason, 'structure');
    }

    /**
     * The declarations the element relies on but inherits, given its start tag:
     * its own prefix's, then the rest. The library's copy names each element by
     * the first declaration of its namespace, so only its own prefix's may come
     * before the element's own, and no unused one is added.
     *
     * @param  \DOMElement  $element
     * @param  string  $attributes
     * @return array{0: string, 1: string}
     */
    private static function inherited(\DOMElement $element, string $attributes): array
    {
        preg_match_all(self::ATTRIBUTE, $attributes, $names);

        $own          = array_flip($names[1]);
        $declarations = ['', ''];

        foreach (self::reliedOn($element) as $prefix => $uri) {
            $name = $prefix === '' ? 'xmlns' : 'xmlns:' . $prefix;

            if (isset($own[$name])) {
                continue;
            }

            // Raw as libxml writes it, so an escaped value stays escaped
            $quote = str_contains($uri, '"') ? '\'' : '"';

            $declarations[$prefix === $element->prefix ? 0 : 1] .= ' ' . $name . '=' . $quote . $uri . $quote;
        }

        return $declarations;
    }

    /**
     * The namespace the element's parent binds to each prefix that a name or an
     * `xsi:type` within the element resolves through it, or that an exclusive
     * canonicalisation's `InclusiveNamespaces` within it lists.
     *
     * @param  \DOMElement  $element
     * @return array<string, string>
     */
    private static function reliedOn(\DOMElement $element): array
    {
        $parent = $element->parentNode;

        if (!$parent instanceof \DOMElement) {
            return [];
        }

        [$users, $listed] = self::prefixUsers($element);
        $relied           = [];

        foreach (array_keys($users + $listed) as $prefix) {
            $uri = $parent->lookupNamespaceURI($prefix === '' ? null : $prefix);

            if ($uri === null || (!isset($listed[$prefix]) && !self::resolvesTo($users[$prefix] ?? [], $prefix, $uri))) {
                continue;
            }

            $relied[$prefix] = $uri;
        }

        return $relied;
    }

    /**
     * The elements within the element whose names or `xsi:type` use each
     * prefix, and the prefixes its `InclusiveNamespaces` list.
     *
     * @param  \DOMElement  $element
     * @return array{0: array<string, list<\DOMElement>>, 1: array<string, true>}
     */
    private static function prefixUsers(\DOMElement $element): array
    {
        $users  = [];
        $listed = [];

        foreach ([$element, ...iterator_to_array($element->getElementsByTagName('*'), false)] as $node) {
            foreach ([$node->prefix, ...self::attributePrefixes($node)] as $prefix) {
                $users[$prefix][] = $node;
            }
        }

        foreach ($element->getElementsByTagNameNS(self::NS_EC, 'InclusiveNamespaces') as $list) {
            $listed += array_fill_keys(self::listedPrefixes($list->getAttribute('PrefixList')), true);
        }

        return [$users, $listed];
    }

    /**
     * The prefixes a `PrefixList` names, the empty one for `#default`.
     *
     * @param  string  $list
     * @return list<string>
     */
    private static function listedPrefixes(string $list): array
    {
        return array_map(
            static fn (string $prefix): string => $prefix === '#default' ? '' : $prefix,
            preg_split('/\s+/', $list, -1, PREG_SPLIT_NO_EMPTY) ?: [],
        );
    }

    /**
     * The prefixes the element's attribute names and its `xsi:type` use, the
     * empty one for an unprefixed type.
     *
     * @param  \DOMElement  $node
     * @return list<string>
     */
    private static function attributePrefixes(\DOMElement $node): array
    {
        $prefixes = array_values(array_filter(
            array_map(static fn (\DOMAttr $attribute): string => $attribute->prefix, iterator_to_array($node->attributes, false)),
            static fn (string $prefix): bool => $prefix !== '',
        ));
        $type = $node->getAttributeNS(self::NS_XSI, 'type');

        if ($type !== '') {
            $prefix     = strstr($type, ':', true);
            $prefixes[] = $prefix === false ? '' : $prefix;
        }

        return $prefixes;
    }

    /**
     * Whether any of the elements resolves the prefix to the namespace; the
     * first that does ends the search.
     *
     * @param  list<\DOMElement>  $nodes
     * @param  string  $prefix
     * @param  string  $uri
     * @return bool
     */
    private static function resolvesTo(array $nodes, string $prefix, string $uri): bool
    {
        foreach ($nodes as $node) {
            if ($node->lookupNamespaceURI($prefix === '' ? null : $prefix) === $uri) {
                return true;
            }
        }

        return false;
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
