<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;

/**
 * Application policy contract (SSO-5.1, SSO-9.2): whether a registered
 * application allows sign-in through an external provider. It is asked before a
 * flow starts for the application and again before a handoff code is issued for
 * it; anything but `allowed` refuses with `application_not_allowed`.
 *
 * The default, `Applications\ConfiguredApplicationPolicy`, answers the
 * application's `external_sign_in` setting, off unless set. Under `laravel-iam`
 * it is bound to `laravel-authentication`'s per-application method list
 * (AUTH-3.7). An implementation answers from current state on each call and
 * keeps nothing of one call for the next (SSO-11.2); an error it cannot answer
 * through propagates, and it never answers `allowed` when it cannot tell.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ApplicationPolicy
{
    /**
     * Whether the application allows sign-in through an external provider.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @return \SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn
     */
    public function externalSignIn(Application $application): ExternalSignIn;
}
