<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

/**
 * Default settings for a well-known identity provider. Given settings override
 * them one by one, so every protocol check still applies.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Preset
{
    /** @var string The pattern a preset's name and protocol match. */
    private const string NAME_PATTERN = '/^[a-z][a-z0-9_]{0,63}$/D';

    /**
     * Constructor.
     *
     * @param  string  $name
     * @param  string  $protocol
     * @param  array<string, mixed>  $settings
     * @param  array<string, string>  $attributeMapping
     * @param  ?string  $organizationClaim
     * @param  ?string  $issuerPattern
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The name the preset is chosen by. */
        public string $name,

        /** The protocol of the connections it fills in. */
        public string $protocol,

        /** The settings it fills in, by name; never a secret. */
        public array $settings = [],

        /** The attribute mapping it fills in: each target attribute by its source. */
        public array $attributeMapping = [],

        /** The claim naming the organisation, for an issuer many share. */
        public ?string $organizationClaim = null,

        /** The pattern each issuer matches, for an issuer naming a directory. */
        public ?string $issuerPattern = null,
    ) {
        if (preg_match(self::NAME_PATTERN, $name) !== 1 || preg_match(self::NAME_PATTERN, $protocol) !== 1) {
            throw new \InvalidArgumentException('A preset\'s name and protocol are lower case: a letter, then up to 63 letters, digits or underscores.');
        }

        if ($organizationClaim === '') {
            throw new \InvalidArgumentException('A preset\'s organisation claim is a name, or none.');
        }
    }

    /**
     * The given settings over the preset's.
     *
     * @param  array<string, mixed>  $settings
     * @return array<string, mixed>
     */
    public function fill(#[\SensitiveParameter] array $settings): array
    {
        return array_replace($this->settings, $settings);
    }

    /**
     * The given attribute mapping over the preset's.
     *
     * @param  array<string, mixed>  $mapping
     * @return array<string, mixed>
     */
    public function fillMapping(array $mapping): array
    {
        return array_replace($this->attributeMapping, $mapping);
    }

    /**
     * Whether many organisations share the issuer.
     *
     * @return bool
     */
    public function isSharedIssuer(): bool
    {
        return $this->organizationClaim !== null;
    }

    /**
     * Whether the issuer equals the preset's or matches its issuer pattern.
     *
     * @param  string  $issuer
     * @return bool
     */
    public function names(string $issuer): bool
    {
        $filled = $this->settings['issuer'] ?? $this->settings['idp_entity_id'] ?? null;

        return $filled === $issuer || ($this->issuerPattern !== null && preg_match($this->issuerPattern, $issuer) === 1);
    }
}
