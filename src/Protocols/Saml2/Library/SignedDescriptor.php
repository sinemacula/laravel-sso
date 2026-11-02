<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\SAML2\XML\md\AbstractSignedMdElement;
use SimpleSAML\XML\Type\IDValue;
use SimpleSAML\XMLSecurity\XML\ds\Signature;

/**
 * A signed `EntityDescriptor` or `EntitiesDescriptor` as the library verifies
 * it, and nothing more: its `ID`, its own `ds:Signature` and the element it was
 * read from (SSO-6.2, SSO-6.11).
 *
 * The library's own descriptors build a typed model of everything they hold,
 * every member of an aggregate included, and refuse the whole aggregate when
 * any member holds a value stricter rules refuse (a relative `mdui:Logo`, an
 * `OrganizationURL` with no scheme, a non-ASCII email address). A signature
 * covers bytes, never that model, so the metadata reader verifies through this
 * element instead and reads only the pinned entity strictly. The library's
 * signature handling is used unchanged: the policy `PinnedVerifier` holds the
 * signature to, the digest over the element's own `ID` reference and the
 * element answered rebuilt from the digested bytes. It is never written.
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
     * The descriptor read from the element: its `ID` and its one signature, if
     * any, with the element kept for the digest.
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
     * A signed descriptor is only ever read, never written.
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
     * The element the descriptor was read from, which the signature covers.
     *
     * @return \DOMElement
     */
    #[\Override]
    protected function getOriginalXML(): \DOMElement
    {
        return $this->getXML();
    }
}
