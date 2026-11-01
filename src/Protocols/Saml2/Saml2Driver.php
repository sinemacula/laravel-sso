<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Protocols\PlaceholderDriver;

/**
 * The `saml2` driver (SSO-2.2, SSO-2.3): reads a SAML 2.0 connection's settings
 * as `Saml2Settings`. Its flows (SP-initiated sign-in, the assertion consumer
 * service, re-initiation and metadata, SSO-5.3, SSO-5.8, SSO-5.9, SSO-6) land
 * in P4; until then it fails every flow closed (see `PlaceholderDriver`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Saml2Driver extends PlaceholderDriver
{
    /** @var string The name the driver is registered under, and a SAML connection's protocol. */
    public const string NAME = 'saml2';

    /** @var string The SAML settings class. */
    private const string SETTINGS = 'SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings';

    /**
     * The SAML settings class.
     *
     * @return string
     */
    #[\Override]
    protected function settingsClass(): string
    {
        return self::SETTINGS;
    }
}
