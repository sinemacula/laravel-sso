<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * A verified `NameID` or `Issuer`. An absent attribute is `null`, never `''`:
 * an absent qualifier and an empty one differ.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NameId implements \JsonSerializable
{
    use HoldsProviderValues;

    /**
     * Constructor.
     *
     * @param  string  $value
     * @param  ?string  $format
     * @param  ?string  $nameQualifier
     * @param  ?string  $spNameQualifier
     * @param  ?string  $spProvidedId
     */
    public function __construct(
        // The element's text, exactly as received
        #[\SensitiveParameter]
        string $value,
        // The `Format` attribute
        ?string $format = null,
        // The `NameQualifier` attribute
        #[\SensitiveParameter]
        ?string $nameQualifier = null,
        // The `SPNameQualifier` attribute
        #[\SensitiveParameter]
        ?string $spNameQualifier = null,
        // The `SPProvidedID` attribute
        #[\SensitiveParameter]
        ?string $spProvidedId = null,
    ) {
        $this->hold([
            'value'             => $value,
            'format'            => $format,
            'name_qualifier'    => $nameQualifier,
            'sp_name_qualifier' => $spNameQualifier,
            'sp_provided_id'    => $spProvidedId,
        ]);
    }

    /**
     * The element's text, exactly as received.
     *
     * @return string
     */
    public function value(): string
    {
        /** @var string */
        return $this->held('value');
    }

    /**
     * The `Format` attribute, or `null` when absent.
     *
     * @return ?string
     */
    public function format(): ?string
    {
        /** @var ?string */
        return $this->held('format');
    }

    /**
     * The `NameQualifier` attribute, or `null` when absent.
     *
     * @return ?string
     */
    public function nameQualifier(): ?string
    {
        /** @var ?string */
        return $this->held('name_qualifier');
    }

    /**
     * The `SPNameQualifier` attribute, or `null` when absent.
     *
     * @return ?string
     */
    public function spNameQualifier(): ?string
    {
        /** @var ?string */
        return $this->held('sp_name_qualifier');
    }

    /**
     * The `SPProvidedID` attribute, or `null` when absent.
     *
     * @return ?string
     */
    public function spProvidedId(): ?string
    {
        /** @var ?string */
        return $this->held('sp_provided_id');
    }
}
