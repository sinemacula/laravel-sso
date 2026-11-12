<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;

/**
 * Decides whether a registered application allows sign-in through an external
 * provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ApplicationPolicy
{
    /**
     * Never answer `allowed` when unsure; let an error propagate instead.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @return \SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn
     */
    public function externalSignIn(Application $application): ExternalSignIn;
}
