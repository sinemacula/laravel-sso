<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Protocols\PlaceholderDriver;

/**
 * The `oidc` driver (SSO-2.2, SSO-2.4): reads an OpenID Connect connection's
 * settings as `OidcSettings`. Its flows (the authorisation code flow, the
 * callback, ID token validation and the relying party's description, SSO-5.4,
 * SSO-5.9, SSO-7) land in P5; until then it fails every flow closed (see
 * `PlaceholderDriver`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OidcDriver extends PlaceholderDriver
{
    /** @var string The name the driver is registered under, and an OIDC connection's protocol. */
    public const string NAME = 'oidc';

    /** @var string The OIDC settings class. */
    private const string SETTINGS = 'SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings';

    /**
     * The OIDC settings class.
     *
     * @return string
     */
    #[\Override]
    protected function settingsClass(): string
    {
        return self::SETTINGS;
    }
}
