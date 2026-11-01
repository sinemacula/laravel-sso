<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications;

use SineMacula\Laravel\Sso\Config\UrlSetting;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;

/**
 * The one way the flows reach an application (SSO-5.1, SSO-5.5, SSO-9.2):
 * admitting the application a request names, and resolving the exact redirect
 * URI a completion for it redirects to.
 *
 * An application is admitted only when it is registered under exactly the name
 * given and the bound `Contracts\ApplicationPolicy` answers `allowed`; an
 * unknown application and one that does not allow external sign-in are both
 * refused with `application_not_allowed`, and the policy is never asked about a
 * name no application is registered under.
 *
 * The redirect URI is answered by the bound `Contracts\RedirectUriResolver`
 * from the registered application and the connection alone, and checked as
 * exactly what a redirect URI may be (`Config\UrlSetting::redirect()`): an
 * answer that is not fails closed with a `LogicException`, a misconfigured
 * binding, naming the application but never the answer.
 *
 * It holds the registry, the policy and the resolver, none of which keeps
 * anything of one request for the next (SSO-11.2); resolve it per request.
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
     * Admit the application registered under exactly the name, once the policy
     * allows it sign-in through an external provider.
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
     * The exact redirect URI of the application, through the connection.
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
