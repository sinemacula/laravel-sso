<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching\Enums;

/**
 * What an outbound request is for (SSO-2.9), which decides the credentials it
 * may carry and whether it may follow a redirect: none to metadata, discovery
 * or a JWKS, which may follow a checked redirect; the connection's client
 * authentication to its token endpoint, and only the access token to UserInfo,
 * neither of which follows any redirect.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FetchPurpose: string
{
    // A SAML identity provider's metadata (SSO-2.8)
    case METADATA = 'metadata';

    // An OpenID provider's discovery document (SSO-2.8)
    case DISCOVERY = 'discovery';

    // An OpenID provider's JSON Web Key Set (SSO-7.3)
    case JWKS = 'jwks';

    // The token request of an authorisation code (SSO-7.2)
    case TOKEN = 'token';

    // The UserInfo request (SSO-7.5)
    case USERINFO = 'userinfo';

    /**
     * Whether a request for this purpose carries a credential, so it follows no
     * redirect.
     *
     * @return bool
     */
    public function isCredentialed(): bool
    {
        return $this === self::TOKEN || $this === self::USERINFO;
    }
}
