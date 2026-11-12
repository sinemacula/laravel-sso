<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications;

use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;

/**
 * The default application policy: external sign-in follows the application's
 * `external_sign_in` setting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredApplicationPolicy implements ApplicationPolicy
{
    /**
     * Whether the application's configuration allows external sign-in.
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
