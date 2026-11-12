<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Applications\Application;

/**
 * Resolves the one exact URI a completion redirects to, from stored state only
 * and never from request input.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RedirectUriResolver
{
    /**
     * Answer `https`, loopback `http` or a private-use scheme, with no user
     * info, fragment or wildcard; anything else is a `LogicException`.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return string
     */
    public function redirectUri(Application $application, SsoConnection $connection): string;
}
