<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching\Enums;

/**
 * The credential an outbound request carries (SSO-2.4, SSO-2.9): one of the
 * three client authentications of a token request (RFC 6749 §2.3, RFC 7523), or
 * the access token of a UserInfo request (RFC 6750).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CredentialKind: string
{
    // The client id and secret in the `Authorization: Basic` header, each
    // form-encoded first (RFC 6749 §2.3.1)
    case CLIENT_SECRET_BASIC = 'client_secret_basic';

    // The client id and secret as `client_id` and `client_secret` in the form
    // body (RFC 6749 §2.3.1)
    case CLIENT_SECRET_POST = 'client_secret_post';

    // A JWT signed with the connection's key as `client_assertion`, with its
    // `client_assertion_type`, and the `client_id`, in the form body (RFC 7523
    // §2.2, OpenID Connect Core §9)
    case PRIVATE_KEY_JWT = 'private_key_jwt';

    // The access token in the `Authorization: Bearer` header (RFC 6750 §2.1)
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
