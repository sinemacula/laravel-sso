<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching\Enums;

/**
 * What an outbound request is for, which decides the credential it may carry
 * and whether it may follow a redirect.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FetchPurpose: string
{
    // A SAML identity provider's metadata
    case METADATA = 'metadata';

    // An OpenID provider's discovery document
    case DISCOVERY = 'discovery';

    // An OpenID provider's JSON Web Key Set
    case JWKS = 'jwks';

    // The token request of an authorisation code
    case TOKEN = 'token';

    // The UserInfo request
    case USERINFO = 'userinfo';

    /**
     * Whether the request carries a credential and so follows no redirect.
     *
     * @return bool
     */
    public function isCredentialed(): bool
    {
        return $this === self::TOKEN || $this === self::USERINFO;
    }
}
