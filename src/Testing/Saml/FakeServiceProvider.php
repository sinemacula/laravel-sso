<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

/**
 * A connection's service provider as the fake SAML identity provider is told of
 * it (SSO-12.4): its entity id and its HTTP-POST assertion consumer service,
 * read from the service provider metadata the package describes, as an identity
 * provider is configured from that metadata.
 *
 * It is what an unsolicited response is made for, since such a response answers
 * no request a test could read them from:
 * `$idp->response($sp->entityId, $sp->assertionConsumerService, $now)`.
 * Metadata that is not one `EntityDescriptor` with an entity id and an
 * HTTP-POST assertion consumer service is a `LogicException` saying which.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FakeServiceProvider
{
    /**
     * Constructor.
     *
     * @param  string  $entityId
     * @param  string  $assertionConsumerService
     */
    private function __construct(

        /** The service provider's entity id, a response's audience. */
        public string $entityId,

        /** Where a response is posted: its `Destination` and its bearer `Recipient`. */
        public string $assertionConsumerService,
    ) {}

    /**
     * The service provider the metadata describes.
     *
     * @param  string  $metadata
     * @return self
     *
     * @throws \LogicException
     */
    public static function fromMetadata(string $metadata): self
    {
        $root = XmlDocument::root($metadata, 'service provider metadata');

        if ($root->namespaceURI !== FakeSamlMetadata::NS_MD || $root->localName !== 'EntityDescriptor') {
            throw new \LogicException('The service provider metadata is not an EntityDescriptor.');
        }

        $entityId = XmlDocument::attribute($root, 'entityID');

        foreach ($root->getElementsByTagNameNS(FakeSamlMetadata::NS_MD, 'AssertionConsumerService') as $service) {

            if ($service->getAttribute('Binding') === FakeSamlMetadata::HTTP_POST) {
                return new self($entityId, XmlDocument::attribute($service, 'Location'));
            }
        }

        throw new \LogicException('The service provider metadata names no HTTP-POST assertion consumer service.');
    }
}
