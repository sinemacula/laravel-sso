<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\SAML2\XML\md\AbstractSignedMdElement;
use SimpleSAML\XML\Type\IDValue;
use SimpleSAML\XMLSecurity\XML\ds\Signature;

/**
 * A signed metadata descriptor reduced to its `ID`, signature and element. The
 * library's own model refuses a whole aggregate over one lax member, so the
 * signature is verified through this instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignedDescriptor extends AbstractSignedMdElement
{
    /**
     * Constructor.
     *
     * @param  ?\SimpleSAML\XML\Type\IDValue  $id
     */
    private function __construct(

        /** The descriptor's `ID`, which its signature's reference must name. */
        private readonly ?IDValue $id,
    ) {}

    /**
     * Read the `ID` and at most one signature, keeping the element for the
     * digest.
     *
     * @param  \DOMElement  $xml
     * @return static
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public static function fromXML(\DOMElement $xml): static
    {
        $descriptors = ['EntityDescriptor', 'EntitiesDescriptor'];

        if ($xml->namespaceURI !== MetadataReader::NS_MD || !in_array($xml->localName, $descriptors, true)) {
            throw new \InvalidArgumentException('Only an EntityDescriptor or an EntitiesDescriptor is a signed descriptor.');
        }

        $signatures = Signature::getChildrenOfClass($xml);

        if (count($signatures) > 1) {
            throw new \InvalidArgumentException('A descriptor holds one signature at most.');
        }

        $descriptor = new self(self::getOptionalAttribute($xml, 'ID', IDValue::class, null));

        if ($signatures !== []) {
            $descriptor->setSignature($signatures[0]);
        }

        $descriptor->setXML($xml);

        return $descriptor;
    }

    /**
     * The descriptor's `ID`.
     *
     * @return ?\SimpleSAML\XML\Type\IDValue
     */
    #[\Override]
    public function getId(): ?IDValue
    {
        return $this->id;
    }

    /**
     * Refuse: a signed descriptor is only ever read.
     *
     * @param  ?\DOMElement  $parent
     * @return \DOMElement
     *
     * @throws \LogicException
     */
    #[\Override]
    public function toUnsignedXML(?\DOMElement $parent = null): \DOMElement
    {
        throw new \LogicException('A signed descriptor is only ever read.');
    }

    /**
     * The element the signature covers.
     *
     * @return \DOMElement
     */
    #[\Override]
    protected function getOriginalXML(): \DOMElement
    {
        return $this->getXML();
    }
}
