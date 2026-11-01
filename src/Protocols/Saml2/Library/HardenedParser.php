<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XML\DOMDocumentFactory;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;

/**
 * The hardened parsing every SAML document goes through (SSO-6.1, SSO-6.11): a
 * posted value's size is capped before it is decoded, and a document's before
 * it is parsed; it is parsed by the library's
 * `DOMDocumentFactory::fromString()`, which refuses a document type declaration
 * before and after parsing (so no entity is declared, resolved or expanded),
 * with `LIBXML_NONET`; it must be valid against the SAML 2.0 schema of its
 * kind, given by its absolute path, while an entity loader refuses everything
 * but the library's own schema files, so validation makes no network request;
 * and no two `ID`, `Id` or `xml:id` attributes anywhere in it share a value.
 *
 * Values are read from a parsed document as text content, so a comment or a
 * processing instruction inside an element cannot change or truncate what is
 * read. A refusal is a `ReadFailure` with `response_invalid` (or the reason
 * given) naming the rule; the libxml error state and the entity loader are
 * restored however it ends. It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HardenedParser
{
    /** @var string The attributes that carry an element's identity, as an XPath union. */
    private const string ID_ATTRIBUTES = '//@ID | //@Id | //@id | //@*[local-name() = "id" and namespace-uri() = "http://www.w3.org/XML/1998/namespace"]';

    /**
     * Decode a posted base64 value of at most the cap, whitespace ignored, or
     * refuse one longer or not base64.
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
     * Parse a document of at most the cap, valid against the schema of its
     * kind, with no `ID` repeated.
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
     * Parse a document of at most the cap, with no schema validation: for
     * reading what correlates a response, which validates nothing.
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
     * Whether the entity loader lets a schema validation load the resource: a
     * file in the library's schema directory, by its real path, and nothing
     * else, so validation reaches no network.
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
     * Validate the document against the schema of its kind, with the entity
     * loader held to the library's schema files.
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
