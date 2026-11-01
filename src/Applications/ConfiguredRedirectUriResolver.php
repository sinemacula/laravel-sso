<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications;

use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;

/**
 * The default redirect URI resolver (SSO-5.5, decision D7): every connection's
 * completions for an application redirect to the application's one configured
 * `redirect_uri`, exactly as configured.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredRedirectUriResolver implements RedirectUriResolver
{
    /**
     * The application's configured redirect URI, whichever the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return string
     */
    #[\Override]
    public function redirectUri(Application $application, SsoConnection $connection): string
    {
        unset($connection);

        return $application->redirectUri;
    }
}
