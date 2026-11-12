<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * One `Attribute` of a verified assertion. A non-text value (an element or
 * `xsi:nil`) is `null` and never mapped or taken as a subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SamlAttribute implements \JsonSerializable
{
    use HoldsProviderValues;

    /**
     * Constructor.
     *
     * @param  string  $name
     * @param  ?string  $nameFormat
     * @param  ?string  $friendlyName
     * @param  list<?string>  $values
     */
    public function __construct(
        // The `Name` attribute
        string $name,
        // The `NameFormat` attribute
        ?string $nameFormat = null,
        // The `FriendlyName` attribute
        ?string $friendlyName = null,
        // Each value's text, `null` for one that is not simple text
        #[\SensitiveParameter]
        array $values = [],
    ) {
        $this->hold(['name' => $name, 'name_format' => $nameFormat, 'friendly_name' => $friendlyName, 'values' => $values]);
    }

    /**
     * The `Name` attribute.
     *
     * @return string
     */
    public function name(): string
    {
        /** @var string */
        return $this->held('name');
    }

    /**
     * The `NameFormat` attribute, or `null` when absent.
     *
     * @return ?string
     */
    public function nameFormat(): ?string
    {
        /** @var ?string */
        return $this->held('name_format');
    }

    /**
     * The `FriendlyName` attribute, or `null` when absent.
     *
     * @return ?string
     */
    public function friendlyName(): ?string
    {
        /** @var ?string */
        return $this->held('friendly_name');
    }

    /**
     * Each value's text in order, `null` for one that is not simple text.
     *
     * @return list<?string>
     */
    public function values(): array
    {
        /** @var list<?string> */
        return $this->held('values');
    }
}
