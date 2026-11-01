<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications;

use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;

/**
 * The default application policy (SSO-5.1): an application allows sign-in
 * through an external provider exactly when its `external_sign_in` setting is
 * on, which it is not unless set, so an application allows nothing until the
 * configuration says it does.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredApplicationPolicy implements ApplicationPolicy
{
    /**
     * Whether the application's configuration allows sign-in through an
     * external provider.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @return \SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn
     */
    #[\Override]
    public function externalSignIn(Application $application): ExternalSignIn
    {
        return $application->externalSignIn ? ExternalSignIn::ALLOWED : ExternalSignIn::NOT_ALLOWED;
    }
}
