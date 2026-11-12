<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications;

use SineMacula\Laravel\Sso\Config\UrlSetting;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;

/**
 * Admits the application a request names and resolves its redirect URI.
 *
 * Resolve it per request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApplicationGate
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\ApplicationRegistry  $registry
     * @param  \SineMacula\Laravel\Sso\Contracts\ApplicationPolicy  $policy
     * @param  \SineMacula\Laravel\Sso\Contracts\RedirectUriResolver  $redirects
     */
    public function __construct(

        /** The registered applications. */
        private ApplicationRegistry $registry,

        /** Whether an application allows sign-in through an external provider. */
        private ApplicationPolicy $policy,

        /** The exact redirect URI of an application, through a connection. */
        private RedirectUriResolver $redirects,
    ) {}

    /**
     * Admit the application registered under exactly the name, if the policy
     * allows external sign-in.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Applications\ApplicationAdmission
     *
     * @throws \InvalidArgumentException
     */
    public function admit(string $name): ApplicationAdmission
    {
        $application = $this->registry->find($name);

        if ($application === null || !$this->policy->externalSignIn($application)->isAllowed()) {
            return ApplicationAdmission::notAllowed();
        }

        return ApplicationAdmission::admitted($application);
    }

    /**
     * The resolver's redirect URI, refused as a misconfigured binding if
     * invalid.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return string
     *
     * @throws \LogicException
     */
    public function redirectUri(Application $application, SsoConnection $connection): string
    {
        $uri = $this->redirects->redirectUri($application, $connection);

        try {
            return UrlSetting::redirect('redirect_uri', $uri);
        } catch (\InvalidArgumentException) {
            throw new \LogicException(sprintf('The bound redirect URI resolver answered the [%s] application with a URI that is not an exact redirect URI.', $application->name));
        }
    }
}
