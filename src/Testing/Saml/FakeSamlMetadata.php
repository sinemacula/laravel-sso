<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

use Carbon\CarbonImmutable;

/**
 * The fake SAML identity provider's metadata (SAML 2.0 Metadata, SSO-2.8,
 * SSO-12.4), built from options a test changes one at a time: by default one
 * unsigned `EntityDescriptor` with an `IDPSSODescriptor` naming its signing
 * certificate, an HTTP-Redirect single sign-on service and the persistent
 * NameID format.
 *
 * `with()` changes any option:
 *
 * - `entity_id`, `sso_url`, `sso_binding`, `post_sso_url` (an HTTP-POST service
 *   besides, or `null`);
 * - `signing_certificates`, `encryption_certificates` (PEM), and
 *   `name_id_formats`;
 * - `valid_until` and `cache_duration` of the entity, `null` for none;
 * - `aggregate`: the entity ids of other entities that share an
 *   `EntitiesDescriptor` with this one (none writes the entity alone), and
 *   `aggregate_valid_until`;
 * - `sign`: `entity` signs the `EntityDescriptor`, `aggregate` the
 *   `EntitiesDescriptor`, `null` neither; `algorithm` and `digest` as the
 *   signer takes them.
 *
 * `signedBy()` signs with another key, an anchor the connection does not trust.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type MetadataOptions array{
 *     entity_id: string, sso_url: string, sso_binding: string, post_sso_url: ?string,
 *     signing_certificates: list<string>, encryption_certificates: list<string>, name_id_formats: list<string>,
 *     valid_until: ?\Carbon\CarbonImmutable, cache_duration: ?string, aggregate: list<string>, aggregate_valid_until: ?\Carbon\CarbonImmutable,
 *     sign: ?string, algorithm: string, digest: string
 * }
 */
final readonly class FakeSamlMetadata
{
    /** @var string The SAML metadata namespace. */
    public const string NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';

    /** @var string The HTTP-Redirect binding. */
    public const string HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    /** @var string The HTTP-POST binding. */
    public const string HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    /** @var string The XML signature namespace. */
    private const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\XmlSigner  $signer
     * @param  MetadataOptions  $options
     */
    public function __construct(

        /** Signs the metadata when asked. */
        private XmlSigner $signer,

        /** What the metadata holds. */
        private array $options,
    ) {}

    /**
     * The options of the provider's unsigned metadata.
     *
     * @param  string  $entityId
     * @param  string  $ssoUrl
     * @param  string  $certificate
     * @return MetadataOptions
     */
    public static function defaults(string $entityId, string $ssoUrl, string $certificate): array
    {
        return [
            'entity_id'               => $entityId,
            'sso_url'                 => $ssoUrl,
            'sso_binding'             => self::HTTP_REDIRECT,
            'post_sso_url'            => null,
            'signing_certificates'    => [$certificate],
            'encryption_certificates' => [],
            'name_id_formats'         => [FakeSamlResponse::PERSISTENT],
            'valid_until'             => null,
            'cache_duration'          => null,
            'aggregate'               => [],
            'aggregate_valid_until'   => null,
            'sign'                    => null,
            'algorithm'               => 'rsa-sha256',
            'digest'                  => 'sha256',
        ];
    }

    /**
     * Metadata with the options given changed and every other kept.
     *
     * @param  array<string, mixed>  $changes
     * @return self
     */
    public function with(array $changes): self
    {
        /** @var MetadataOptions $options */
        $options = [...$this->options, ...$changes];

        return new self($this->signer, $options);
    }

    /**
     * Metadata whose signature another key makes.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\XmlSigner  $signer
     * @return self
     */
    public function signedBy(XmlSigner $signer): self
    {
        return new self($signer, $this->options);
    }

    /**
     * The metadata's XML.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function toXml(): string
    {
        try {
            return $this->written();
        } catch (\DOMException $exception) {
            throw new \LogicException('The fake identity provider could not write its metadata.', 0, $exception);
        }
    }

    /**
     * What `toXml()` answers, a DOM failure let through.
     *
     * @return string
     *
     * @throws \LogicException
     * @throws \DOMException
     */
    private function written(): string
    {
        $entity   = $this->entity($this->options['entity_id'], $this->options['valid_until']);
        $others   = array_map(fn (string $entityId): string => $this->entity($entityId, null), $this->options['aggregate']);
        $xml      = $this->options['aggregate'] === [] ? $entity : $this->aggregate([...$others, $entity]);
        $document = new \DOMDocument;

        $document->loadXML($xml, LIBXML_NONET);

        $this->signed($document);

        return (string) $document->saveXML($document->documentElement);
    }

    /**
     * Sign the document's entity or aggregate when asked.
     *
     * @param  \DOMDocument  $document
     * @return void
     *
     * @throws \LogicException
     */
    private function signed(\DOMDocument $document): void
    {
        $sign    = $this->options['sign'];
        $options = ['algorithm' => $this->options['algorithm'], 'digest' => $this->options['digest']];
        $root    = $document->documentElement;

        if ($sign === null || $root === null) {
            return;
        }

        $target = $sign === 'aggregate' ? $root : self::entityElement($document, $this->options['entity_id']);

        $this->signer->sign($target, $options);
    }

    /**
     * The `EntitiesDescriptor` holding the entities.
     *
     * @param  list<string>  $entities
     * @return string
     */
    private function aggregate(array $entities): string
    {
        return '<md:EntitiesDescriptor xmlns:md="' . self::NS_MD . '" ID="_aggregate"'
            . self::attribute('validUntil', self::instant($this->options['aggregate_valid_until'])) . '>'
            . implode('', $entities)
            . '</md:EntitiesDescriptor>';
    }

    /**
     * One `EntityDescriptor` with its `IDPSSODescriptor`.
     *
     * @param  string  $entityId
     * @param  ?\Carbon\CarbonImmutable  $validUntil
     * @return string
     */
    private function entity(string $entityId, ?CarbonImmutable $validUntil): string
    {
        $signing    = array_map(static fn (string $certificate): string => self::keyDescriptor('signing', $certificate), $this->options['signing_certificates']);
        $encryption = array_map(static fn (string $certificate): string => self::keyDescriptor('encryption', $certificate), $this->options['encryption_certificates']);
        $formats    = array_map(
            static fn (string $format): string => '<md:NameIDFormat>' . htmlspecialchars($format, ENT_XML1) . '</md:NameIDFormat>',
            $this->options['name_id_formats'],
        );
        $post = $this->options['post_sso_url'] === null ? '' : self::service(self::HTTP_POST, $this->options['post_sso_url']);

        return '<md:EntityDescriptor xmlns:md="' . self::NS_MD . '"'
            . self::attribute('ID', '_' . substr(hash('sha256', $entityId), 0, 16))
            . self::attribute('entityID', $entityId)
            . self::attribute('validUntil', self::instant($validUntil))
            . self::attribute('cacheDuration', $this->options['cache_duration']) . '>'
            . '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            . implode('', [...$signing, ...$encryption, ...$formats])
            . self::service($this->options['sso_binding'], $this->options['sso_url'])
            . $post
            . '</md:IDPSSODescriptor></md:EntityDescriptor>';
    }

    /**
     * One `SingleSignOnService` of the binding at the location.
     *
     * @param  string  $binding
     * @param  string  $location
     * @return string
     */
    private static function service(string $binding, string $location): string
    {
        return '<md:SingleSignOnService' . self::attribute('Binding', $binding) . self::attribute('Location', $location) . '/>';
    }

    /**
     * One `KeyDescriptor` of the use, carrying the certificate.
     *
     * @param  string  $use
     * @param  string  $certificate
     * @return string
     */
    private static function keyDescriptor(string $use, string $certificate): string
    {
        $body = (string) preg_replace('/-----[^-]+-----|\s+/', '', $certificate);

        return '<md:KeyDescriptor use="' . $use . '"><ds:KeyInfo xmlns:ds="' . self::NS_DS . '"><ds:X509Data><ds:X509Certificate>'
            . $body . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';
    }

    /**
     * The `EntityDescriptor` of the entity id in the document.
     *
     * @param  \DOMDocument  $document
     * @param  string  $entityId
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    private static function entityElement(\DOMDocument $document, string $entityId): \DOMElement
    {
        foreach ($document->getElementsByTagNameNS(self::NS_MD, 'EntityDescriptor') as $element) {
            if ($element->getAttribute('entityID') === $entityId) {
                return $element;
            }
        }

        throw new \LogicException('The fake metadata holds the entity it signs.');
    }

    /**
     * An attribute with its value escaped, or nothing for `null`.
     *
     * @param  string  $name
     * @param  ?string  $value
     * @return string
     */
    private static function attribute(string $name, ?string $value): string
    {
        return $value === null ? '' : ' ' . $name . '="' . htmlspecialchars($value, ENT_XML1 | ENT_QUOTES) . '"';
    }

    /**
     * An instant as SAML writes one, or `null`.
     *
     * @param  ?\Carbon\CarbonImmutable  $instant
     * @return ?string
     */
    private static function instant(?CarbonImmutable $instant): ?string
    {
        return $instant?->utc()->format('Y-m-d\TH:i:s\Z');
    }
}
