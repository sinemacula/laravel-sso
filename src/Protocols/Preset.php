<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

/**
 * Settings for a well-known identity provider, as data (SSO-2.2): the protocol,
 * the settings and the attribute mapping it fills in, and, for an issuer shared
 * by many organisations, the claim or attribute naming the organisation a
 * result belongs to, which linking by a verified domain requires (SSO-8.8).
 *
 * A preset is never a code path of its own: it fills in a connection's
 * settings, and what an administrator gives replaces what it fills in, setting
 * by setting, so every check of the protocol applies as it does to settings
 * entered by hand.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Preset
{
    /** @var string The pattern a preset's name matches: a lower-case letter, then lower-case letters, digits or underscores. */
    private const string NAME_PATTERN = '/^[a-z][a-z0-9_]{0,63}$/D';

    /**
     * Constructor.
     *
     * @param  string  $name
     * @param  string  $protocol
     * @param  array<string, mixed>  $settings
     * @param  array<string, string>  $attributeMapping
     * @param  ?string  $organizationClaim
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

        /** For an issuer shared by many organisations, the claim or attribute naming the organisation. */
        public ?string $organizationClaim = null,
    ) {
        if (preg_match(self::NAME_PATTERN, $name) !== 1 || preg_match(self::NAME_PATTERN, $protocol) !== 1) {
            throw new \InvalidArgumentException('A preset\'s name and protocol are lower case: a letter, then up to 63 letters, digits or underscores.');
        }

        if ($organizationClaim === '') {
            throw new \InvalidArgumentException('A preset\'s organisation claim is a name, or none.');
        }
    }

    /**
     * The settings given, with what the preset fills in where none is given.
     * The settings may carry a secret, so a trace shows them redacted.
     *
     * @param  array<string, mixed>  $settings
     * @return array<string, mixed>
     */
    public function fill(#[\SensitiveParameter] array $settings): array
    {
        return array_replace($this->settings, $settings);
    }

    /**
     * The attribute mapping given, with what the preset fills in for each
     * target none is given for.
     *
     * @param  array<string, mixed>  $mapping
     * @return array<string, mixed>
     */
    public function fillMapping(array $mapping): array
    {
        return array_replace($this->attributeMapping, $mapping);
    }

    /**
     * Whether the preset is for an issuer many organisations share, whose
     * results are told apart by its organisation claim.
     *
     * @return bool
     */
    public function isSharedIssuer(): bool
    {
        return $this->organizationClaim !== null;
    }
}
