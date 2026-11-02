<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\CertificateInspector;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Metadata\MetadataSettings;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;

/**
 * Reads an identity provider's SAML 2.0 metadata for one pinned entity, by the
 * metadata validation profile (SSO-2.8, SSO-6.1, SSO-6.11): the package's one
 * reader of metadata, for an import and for a refresh alike, and the only class
 * besides the response adapter's that calls the SAML library.
 *
 * 1. The document is capped at `sso.metadata.max_bytes` before it is parsed,
 *    the cap a metadata fetch is held to too, and parsed hardened with no `ID`
 *    repeated anywhere in it (`HardenedParser`). libxml's default limits bound
 *    a single text node, name or attribute, never the document's size, so an
 *    aggregate of tens of MiB parses without `LIBXML_PARSEHUGE`, which stays
 *    off: no value in metadata comes near those limits, and the cap bounds the
 *    document.
 * 2. Its root is an `EntityDescriptor` or an `EntitiesDescriptor`. Exactly one
 *    `EntityDescriptor` anywhere in it has the pinned entity id, compared
 *    exactly: none is `metadata_entity_not_found`, more than one, wherever it
 *    hides, `metadata_invalid`. The one chosen is the root, or a child of an
 *    `EntitiesDescriptor` that is itself the root or such a child, checked by
 *    walking its ancestors, so an entity wrapped anywhere else is refused.
 * 3. Within the chosen entity, the only signature allowed is its own, a child
 *    of the entity; one anywhere else in it is refused. The chosen entity, and
 *    only it, must be valid against the metadata schema (`schema`): the other
 *    members of an aggregate are never validated, so a member a federation
 *    lists with a value the schema refuses never refuses the rest.
 * 4. With an anchor set (the connection's metadata signing certificates), the
 *    entity must be covered by a signature, its own or an enclosing
 *    `EntitiesDescriptor`'s, and every signature on that path must verify with
 *    an anchor through `PinnedVerifier`, each signed element copied into a
 *    document of its own first, as the library needs (`saml-library.md`), and
 *    verified as a `SignedDescriptor`, which models the signature alone. No
 *    signature, or one that does not verify, is `metadata_signature_invalid`.
 *    The entity is then read from the element parsed from the bytes the
 *    innermost signature on its path digested, never from the document given.
 *    Without anchors, signatures are not read. No member is modelled by the
 *    library's `EntityDescriptor`, the chosen one included: its stricter rules
 *    (a URL with a scheme, an ASCII email address, a `validUntil` in UTC) judge
 *    values the reader never reads, and the schema has judged the entity.
 * 5. Its expiry is the earliest `validUntil` of the entity and every descriptor
 *    enclosing it (`cacheDuration` is ignored); one not after the clock's now
 *    is `metadata_expired`.
 * 6. The entity has exactly one `IDPSSODescriptor` that supports the SAML 2.0
 *    protocol, with a single sign-on service of the HTTP-Redirect or HTTP-POST
 *    binding (the first of each), the connection's current binding preferred,
 *    then HTTP-Redirect; and at least one RSA signing certificate, from a
 *    `KeyDescriptor` of use `signing` or of none. Encryption certificates come
 *    from one of use `encryption` or of none. A certificate the package cannot
 *    use (not RSA, too weak, unreadable) is ignored; one repeated is kept once,
 *    by fingerprint.
 *
 * Values are read as text content from the elements at the positions checked,
 * which the verified signatures cover, so a comment or a processing instruction
 * cannot change one. The answer is an `IdpMetadata`, read or refused with the
 * rule's name; the reader never logs or keeps the document. It holds the
 * parser, the verifier, the certificate inspector, the metadata settings and
 * the clock, none of which keeps anything between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-import-type MetadataValues from \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
 * @phpstan-import-type Certificate from \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
 */
final readonly class MetadataReader
{
    /** @var string The SAML metadata namespace. */
    public const string NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';

    /** @var string The XML signature namespace. */
    public const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /** @var string The SAML 2.0 protocol, as `protocolSupportEnumeration` names it. */
    public const string SAML2_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /** @var array<string, string> The bindings a single sign-on service may have, by URI, as the connection names them, in the order preferred. */
    public const array BINDINGS = [
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' => 'http_redirect',
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'     => 'http_post',
    ];

    /** @var string An `xs:dateTime`: a date, a time with optional fractions, and an optional zone. */
    private const string DATE_TIME = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$/D';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser  $parser
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\PinnedVerifier  $verifier
     * @param  \SineMacula\Laravel\Sso\Keys\CertificateInspector  $inspector
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Caps and parses the document, and schema-validates the entity. */
        private HardenedParser $parser,

        /** Verifies each signature with the anchors. */
        private PinnedVerifier $verifier,

        /** Reads and judges each certificate. */
        private CertificateInspector $inspector,

        /** The cap the document is held to. */
        private MetadataSettings $settings,

        /** The clock the expiry is judged against. */
        private Clock $clock,
    ) {}

    /**
     * The most bytes a metadata document may hold, which a fetch of one is held
     * to as well.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function maxBytes(): int
    {
        return $this->settings->maxBytes();
    }

    /**
     * The metadata of the pinned entity, every signature on its path verified
     * with an anchor when anchors are given, or why it was refused.
     *
     * @param  string  $xml
     * @param  string  $entityId
     * @param  list<string>  $anchors
     * @param  ?string  $binding
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
     *
     * @throws \InvalidArgumentException
     */
    public function read(#[\SensitiveParameter] string $xml, string $entityId, array $anchors = [], ?string $binding = null): IdpMetadata
    {
        $maxBytes = $this->maxBytes();

        try {
            $document = $this->parser->loadUnique($xml, $maxBytes, FailureReason::METADATA_INVALID);
            $entity   = self::entity($document, $entityId);
            $path     = self::path($entity);

            $this->parser->validateElement($entity, MessageKind::METADATA, FailureReason::METADATA_INVALID);

            if ($anchors !== []) {
                $path = $this->verifiedPath($path, $anchors);
            }

            return IdpMetadata::read($this->values($path[0], $path, $binding));
        } catch (ReadFailure $failure) {
            return IdpMetadata::refused($failure->reason, $failure->detail);
        }
    }

    /**
     * The one `EntityDescriptor` with the entity id, whose only signature, if
     * any, is its own.
     *
     * @param  \DOMDocument  $document
     * @param  string  $entityId
     * @return \DOMElement
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function entity(\DOMDocument $document, string $entityId): \DOMElement
    {
        $root = $document->documentElement;

        if ($root === null || !self::isDescriptor($root)) {
            throw new ReadFailure(FailureReason::METADATA_INVALID, 'not_metadata');
        }

        $matches = self::matching($document, $entityId);
        $entity  = $matches[0] ?? throw new ReadFailure(FailureReason::METADATA_ENTITY_NOT_FOUND, 'entity_not_found');

        if (count($matches) > 1) {
            throw new ReadFailure(FailureReason::METADATA_INVALID, 'duplicate_entity');
        }

        self::assertOwnSignatureOnly($entity);

        return $entity;
    }

    /**
     * Every `EntityDescriptor` anywhere in the document whose entity id is
     * exactly the one given; none for an empty one.
     *
     * @param  \DOMDocument  $document
     * @param  string  $entityId
     * @return list<\DOMElement>
     */
    private static function matching(\DOMDocument $document, string $entityId): array
    {
        $matches = [];

        foreach ($document->getElementsByTagNameNS(self::NS_MD, 'EntityDescriptor') as $candidate) {
            if ($entityId === '' || $candidate->getAttribute('entityID') !== $entityId) {
                continue;
            }

            $matches[] = $candidate;
        }

        return $matches;
    }

    /**
     * Refuse an entity holding a signature anywhere but as its own child.
     *
     * @param  \DOMElement  $entity
     * @return void
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function assertOwnSignatureOnly(\DOMElement $entity): void
    {
        foreach ($entity->getElementsByTagNameNS(self::NS_DS, 'Signature') as $signature) {

            $parent = $signature->parentNode;

            if ($parent === null || !$entity->isSameNode($parent)) {
                throw new ReadFailure(FailureReason::METADATA_INVALID, 'signature_location');
            }
        }
    }

    /**
     * The entity, then each descriptor enclosing it out to the root, each an
     * `EntitiesDescriptor`.
     *
     * @param  \DOMElement  $entity
     * @return non-empty-list<\DOMElement>
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function path(\DOMElement $entity): array
    {
        $path = [$entity];

        for ($node = $entity->parentNode; $node instanceof \DOMElement; $node = $node->parentNode) {

            if (!self::isMetadata($node, 'EntitiesDescriptor')) {
                throw new ReadFailure(FailureReason::METADATA_INVALID, 'entity_location');
            }

            $path[] = $node;
        }

        return $path;
    }

    /**
     * The path as the anchors verified it: a signature required on it and every
     * one there verified, then the entity, and each descriptor enclosing it
     * within the innermost signed one, read from the element parsed from the
     * bytes that signature digested, followed by the descriptors enclosing that
     * one.
     *
     * @param  non-empty-list<\DOMElement>  $path
     * @param  list<string>  $anchors
     * @return non-empty-list<\DOMElement>
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private function verifiedPath(array $path, array $anchors): array
    {
        $signed   = array_filter($path, static fn (\DOMElement $element): bool => self::children($element, self::NS_DS, 'Signature') !== []);
        $digested = [];

        if ($signed === []) {
            throw new ReadFailure(FailureReason::METADATA_SIGNATURE_INVALID, 'unsigned');
        }

        $reason = FailureReason::METADATA_SIGNATURE_INVALID;

        foreach ($signed as $index => $element) {
            $digested[$index] = $this->verifier->verifiedElement(self::reRooted($element), $anchors, PinnedVerifier::SIGNATURE_ALGORITHMS, $reason)[1];
        }

        $innermost = array_key_first($digested);
        $document  = $digested[$innermost]->ownerDocument;
        $entity    = $document === null ? null : self::matching($document, $path[0]->getAttribute('entityID'))[0] ?? null;

        if ($entity === null) {
            throw new ReadFailure(FailureReason::METADATA_INVALID, 'structure');
        }

        return [...self::path($entity), ...array_slice($path, $innermost + 1)];
    }

    /**
     * The signed descriptor copied into a document of its own, so the library
     * digests the descriptor rather than the document that held it, as a
     * descriptor that models its signature alone.
     *
     * @param  \DOMElement  $element
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Library\SignedDescriptor
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function reRooted(\DOMElement $element): SignedDescriptor
    {
        try {
            $document = new \DOMDocument('1.0', 'UTF-8');
            $copy     = $document->importNode($element, true);

            if (!$copy instanceof \DOMElement) {
                throw new ReadFailure(FailureReason::METADATA_INVALID, 'structure');
            }

            $document->appendChild($copy);

            return SignedDescriptor::fromXML($copy);
        } catch (\Throwable) {
            throw new ReadFailure(FailureReason::METADATA_INVALID, 'structure');
        }
    }

    /**
     * What the entity's metadata holds, once it has not expired.
     *
     * @param  \DOMElement  $entity
     * @param  non-empty-list<\DOMElement>  $path
     * @param  ?string  $binding
     * @return MetadataValues
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private function values(\DOMElement $entity, array $path, ?string $binding): array
    {
        $validUntil = self::validUntil($path);

        if ($validUntil !== null && $validUntil <= $this->clock->now()) {
            throw new ReadFailure(FailureReason::METADATA_EXPIRED, 'expired');
        }

        $descriptor         = self::descriptor($entity);
        [$ssoBinding, $url] = self::service($descriptor, $binding);
        $signing            = $this->certificates($descriptor, 'signing');

        if ($signing === []) {
            throw new ReadFailure(FailureReason::METADATA_INVALID, 'signing_certificate');
        }

        return [
            'entity_id'               => $entity->getAttribute('entityID'),
            'sso_url'                 => $url,
            'sso_binding'             => $ssoBinding,
            'signing_certificates'    => $signing,
            'encryption_certificates' => $this->certificates($descriptor, 'encryption'),
            'name_id_formats'         => self::nameIdFormats($descriptor),
            'valid_until'             => $validUntil,
        ];
    }

    /**
     * The earliest `validUntil` on the path, in UTC, or `null` when none
     * carries one.
     *
     * @param  non-empty-list<\DOMElement>  $path
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function validUntil(array $path): ?CarbonImmutable
    {
        $earliest = null;

        foreach ($path as $element) {

            if (!$element->hasAttribute('validUntil')) {
                continue;
            }

            $instant  = self::instant($element->getAttribute('validUntil'));
            $earliest = $earliest === null ? $instant : $earliest->min($instant);
        }

        return $earliest;
    }

    /**
     * The `xs:dateTime` as an instant in UTC, one with no zone read as UTC; a
     * form the schema allows beyond a four-digit year is refused.
     *
     * @param  string  $value
     * @return \Carbon\CarbonImmutable
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function instant(string $value): CarbonImmutable
    {
        if (preg_match(self::DATE_TIME, $value) !== 1) {
            throw new ReadFailure(FailureReason::METADATA_INVALID, 'valid_until');
        }

        return CarbonImmutable::parse($value, 'UTC')->utc();
    }

    /**
     * The entity's one `IDPSSODescriptor` that supports the SAML 2.0 protocol.
     *
     * @param  \DOMElement  $entity
     * @return \DOMElement
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function descriptor(\DOMElement $entity): \DOMElement
    {
        $supporting = array_values(array_filter(
            self::children($entity, self::NS_MD, 'IDPSSODescriptor'),
            static fn (\DOMElement $descriptor): bool => in_array(self::SAML2_PROTOCOL, preg_split('/\s+/', $descriptor->getAttribute('protocolSupportEnumeration')) ?: [], true),
        ));

        if (count($supporting) !== 1) {
            throw new ReadFailure(FailureReason::METADATA_INVALID, 'idp_descriptor');
        }

        return $supporting[0];
    }

    /**
     * The binding and URL of the single sign-on service chosen: the first of
     * the binding preferred, else the first of HTTP-Redirect, then HTTP-POST.
     *
     * @param  \DOMElement  $descriptor
     * @param  ?string  $preferred
     * @return array{0: string, 1: string}
     *
     * @throws \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ReadFailure
     */
    private static function service(\DOMElement $descriptor, ?string $preferred): array
    {
        $services = [];

        foreach (self::children($descriptor, self::NS_MD, 'SingleSignOnService') as $service) {

            $binding = self::BINDINGS[$service->getAttribute('Binding')] ?? null;

            if ($binding === null || isset($services[$binding])) {
                continue;
            }

            $services[$binding] = $service->getAttribute('Location');
        }

        foreach ([$preferred, ...array_values(self::BINDINGS)] as $binding) {
            if ($binding !== null && isset($services[$binding])) {
                return [$binding, $services[$binding]];
            }
        }

        throw new ReadFailure(FailureReason::METADATA_INVALID, 'sso_service');
    }

    /**
     * The RSA certificates of the descriptor's key descriptors of the use, or
     * of none, each with its fingerprint, once each, in document order.
     *
     * @param  \DOMElement  $descriptor
     * @param  string  $use
     * @return list<Certificate>
     */
    private function certificates(\DOMElement $descriptor, string $use): array
    {
        $certificates = [];

        foreach (self::children($descriptor, self::NS_MD, 'KeyDescriptor') as $key) {

            $keyUse = $key->getAttribute('use');

            if ($keyUse !== '' && $keyUse !== $use) {
                continue;
            }

            foreach ($key->getElementsByTagNameNS(self::NS_DS, 'X509Certificate') as $certificate) {

                $read = $this->certificate($certificate->textContent);

                if ($read === null) {
                    continue;
                }

                $certificates[$read['fingerprint']] ??= $read;
            }
        }

        return array_values($certificates);
    }

    /**
     * The base64 body of an `X509Certificate`, decoded and encoded again as a
     * canonical PEM, and its fingerprint, when it is an RSA certificate the
     * package accepts; `null` otherwise, an empty body included.
     *
     * @param  string  $body
     * @return ?Certificate
     */
    private function certificate(string $body): ?array
    {
        $der   = (string) base64_decode((string) preg_replace('/\s+/', '', $body), true);
        $pem   = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
        $facts = $this->inspector->inspect($pem)['facts'];

        return $facts !== null && $facts['type'] === KeyType::RSA ? ['certificate' => $facts['certificate'], 'fingerprint' => $facts['fingerprint']] : null;
    }

    /**
     * The NameID formats the descriptor offers, trimmed, once each, in document
     * order.
     *
     * @param  \DOMElement  $descriptor
     * @return list<string>
     */
    private static function nameIdFormats(\DOMElement $descriptor): array
    {
        $formats = array_map(static fn (\DOMElement $format): string => trim($format->textContent), self::children($descriptor, self::NS_MD, 'NameIDFormat'));

        return array_values(array_unique(array_filter($formats, static fn (string $format): bool => $format !== '')));
    }

    /**
     * The element's children of the namespace and local name, in order.
     *
     * @param  \DOMElement  $element
     * @param  string  $namespace
     * @param  string  $name
     * @return list<\DOMElement>
     */
    private static function children(\DOMElement $element, string $namespace, string $name): array
    {
        $children = [];

        foreach ($element->childNodes as $child) {
            if (!$child instanceof \DOMElement || $child->namespaceURI !== $namespace || $child->localName !== $name) {
                continue;
            }

            $children[] = $child;
        }

        return $children;
    }

    /**
     * Whether the element is an `EntityDescriptor` or an `EntitiesDescriptor`.
     *
     * @param  \DOMElement  $element
     * @return bool
     */
    private static function isDescriptor(\DOMElement $element): bool
    {
        return self::isMetadata($element, 'EntityDescriptor') || self::isMetadata($element, 'EntitiesDescriptor');
    }

    /**
     * Whether the element is the metadata element of the local name.
     *
     * @param  \DOMElement  $element
     * @param  string  $name
     * @return bool
     */
    private static function isMetadata(\DOMElement $element, string $name): bool
    {
        return $element->namespaceURI === self::NS_MD && $element->localName === $name;
    }
}
