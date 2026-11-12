<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching\Enums;

/**
 * The credential an outbound request carries: a token request's client
 * authentication (RFC 6749 section 2.3, RFC 7523) or a UserInfo access token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CredentialKind: string
{
    // Client id and secret in the Basic header, each form-encoded first
    case CLIENT_SECRET_BASIC = 'client_secret_basic';

    // Client id and secret in the form body
    case CLIENT_SECRET_POST = 'client_secret_post';

    // A JWT signed with the connection's key as `client_assertion` (RFC 7523)
    case PRIVATE_KEY_JWT = 'private_key_jwt';

    // The access token in the Bearer header
    case ACCESS_TOKEN = 'access_token';

    /**
     * Whether the credential authenticates the client at a token endpoint.
     *
     * @return bool
     */
    public function isClientAuthentication(): bool
    {
        return $this !== self::ACCESS_TOKEN;
    }
}
