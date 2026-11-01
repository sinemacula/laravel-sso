<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Applications\Application;

/**
 * Redirect URI resolver contract (SSO-5.5, decision D7): the one exact URI a
 * completion of a flow for the application, through the connection, redirects
 * to, carrying the handoff code or the failure code and the request's public
 * reference.
 *
 * It is given only what the package trusts, the registered application and the
 * connection the authorisation request names, read from storage, and never
 * anything from the request: no request input chooses or alters a redirect, and
 * the package carries no return URL (the application keeps its own, keyed by
 * its verifier). The URI is used exactly as answered, with no wildcard, pattern
 * or added path, and must be `https`, `http` on `127.0.0.1` or `[::1]`, or a
 * private-use scheme a native application registers (RFC 8252 §7.1), with no
 * user information, fragment or wildcard; the package refuses any other answer
 * as a misconfiguration (`LogicException`).
 *
 * The default, `Applications\ConfiguredRedirectUriResolver`, answers the
 * application's `redirect_uri` setting; an application binds its own to answer
 * a per-client address without a schema change. An implementation keeps nothing
 * of one call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RedirectUriResolver
{
    /**
     * The exact redirect URI for the application, through the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return string
     */
    public function redirectUri(Application $application, SsoConnection $connection): string;
}
