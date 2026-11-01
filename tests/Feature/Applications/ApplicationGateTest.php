<?php

declare(strict_types = 1);

namespace Tests\Feature\Applications;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationAdmission;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Applications\ConfiguredApplicationPolicy;
use SineMacula\Laravel\Sso\Applications\ConfiguredRedirectUriResolver;
use SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\RedirectUriResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for how the flows reach an application: admitted only when
 * registered under exactly its name and allowed by the bound policy, refused
 * alike otherwise; and its redirect URI resolved by the bound resolver from the
 * application and the connection alone, exactly as answered, a malformed answer
 * failing closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationGate::class)]
#[CoversClass(ApplicationAdmission::class)]
#[CoversClass(ConfiguredApplicationPolicy::class)]
#[CoversClass(ConfiguredRedirectUriResolver::class)]
final class ApplicationGateTest extends TestCase
{
    /**
     * Register an application that allows external sign-in and one that does
     * not.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.applications', [
            'web'   => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
            'admin' => ['redirect_uri' => 'https://admin.example.com/sso'],
        ]);
    }

    /**
     * By default, an application allows external sign-in exactly when its
     * configuration says so; an unknown one is refused the same way.
     *
     * @return void
     */
    public function testAdmitsOnlyARegisteredApplicationThatAllowsExternalSignIn(): void
    {
        $gate = app(ApplicationGate::class);

        $admitted = $gate->admit('web');

        self::assertTrue($admitted->isAdmitted());
        self::assertFalse($admitted->isRefused());
        self::assertSame('web', $admitted->application?->name);
        self::assertNull($admitted->reason);

        foreach (['admin', 'unknown', 'Web', ''] as $name) {

            $refused = $gate->admit($name);

            self::assertTrue($refused->isRefused(), $name);
            self::assertFalse($refused->isAdmitted(), $name);
            self::assertNull($refused->application, $name);
            self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $refused->reason, $name);
        }
    }

    /**
     * A bound policy decides for every registered application, and is never
     * asked about a name no application is registered under.
     *
     * @return void
     */
    public function testABoundPolicyDecides(): void
    {
        $policy = new class implements ApplicationPolicy {
            /** @var list<string> The applications asked about, in order. */
            public array $asked = [];

            /**
             * Allow `admin` only.
             *
             * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
             * @return \SineMacula\Laravel\Sso\Applications\Enums\ExternalSignIn
             */
            #[\Override]
            public function externalSignIn(Application $application): ExternalSignIn
            {
                $this->asked[] = $application->name;

                return $application->name === 'admin' ? ExternalSignIn::ALLOWED : ExternalSignIn::NOT_ALLOWED;
            }
        };

        $this->app?->instance(ApplicationPolicy::class, $policy);

        $gate = app(ApplicationGate::class);

        self::assertTrue($gate->admit('admin')->isAdmitted());
        self::assertTrue($gate->admit('web')->isRefused());
        self::assertTrue($gate->admit('unknown')->isRefused());
        self::assertSame(['admin', 'web'], $policy->asked);
    }

    /**
     * The default resolver answers the application's configured redirect URI
     * exactly, whichever the connection.
     *
     * @return void
     */
    public function testResolvesTheConfiguredRedirectUri(): void
    {
        config()->set('sso.applications.web.redirect_uri', 'https://app.example.com/sso?client=web');

        $gate        = app(ApplicationGate::class);
        $application = $gate->admit('web')->application;

        self::assertNotNull($application);
        self::assertSame('https://app.example.com/sso?client=web', $gate->redirectUri($application, new ExampleConnection('oidc')));
        self::assertSame('https://app.example.com/sso?client=web', $gate->redirectUri($application, new ExampleConnection('saml2')));
    }

    /**
     * A bound resolver is given the application and the connection, and its
     * answer is used exactly; a native application's scheme is a redirect URI.
     *
     * @return void
     */
    public function testABoundResolverAnswersPerConnection(): void
    {
        $this->app?->instance(RedirectUriResolver::class, new class implements RedirectUriResolver {
            /**
             * A native scheme per connection.
             *
             * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return string
             */
            #[\Override]
            public function redirectUri(Application $application, SsoConnection $connection): string
            {
                return "com.example.{$application->name}:/sso/{$connection->getConnectionId()}";
            }
        });

        $gate        = app(ApplicationGate::class);
        $application = $gate->admit('web')->application;

        self::assertNotNull($application);
        self::assertSame('com.example.web:/sso/01jbexampleconnection00000', $gate->redirectUri($application, new ExampleConnection('oidc')));
    }

    /**
     * A bound resolver's answer that is not an exact redirect URI fails closed,
     * naming the application and never the answer.
     *
     * @return void
     */
    public function testAMalformedAnswerFailsClosed(): void
    {
        $this->app?->instance(RedirectUriResolver::class, new class implements RedirectUriResolver {
            /**
             * A wildcard.
             *
             * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @return string
             */
            #[\Override]
            public function redirectUri(Application $application, SsoConnection $connection): string
            {
                return 'https://*.attacker.example/sso';
            }
        });

        $gate        = app(ApplicationGate::class);
        $application = $gate->admit('web')->application;

        self::assertNotNull($application);

        $this->expectExceptionObject(new \LogicException('The bound redirect URI resolver answered the [web] application with a URI that is not an exact redirect URI.'));

        $gate->redirectUri($application, new ExampleConnection('oidc'));
    }
}
