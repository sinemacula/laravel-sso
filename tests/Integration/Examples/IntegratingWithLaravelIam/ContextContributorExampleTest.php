<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\ExampleTestCase;
use Tests\Integration\Examples\SiblingStandIns;

/**
 * The adapter's `sso` contributor of
 * `docs/guides/integrating-with-laravel-iam.md` (SSO-9.10, SSO-12.5), on the
 * shared example harness, against the examples' stand-ins for
 * `laravel-authentication`'s registry, subject, provenance and provider context
 * (`IntegratingWithLaravelIam/Authentication`), which mirror its real
 * signatures: the adapter's service provider registers it under `sso`, once,
 * and a second registration is refused; for a session a sign-in through the
 * package established, it answers every key of the captured provenance's
 * projection without its prefix, after authentication kept the provider context
 * as JSON; and a session no external provider established contributes none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationContext::class)]
final class ContextContributorExampleTest extends ExampleTestCase
{
    /**
     * Load the stand-ins, bind authentication's registry as its own provider
     * does, and register the adapter's service provider.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        SiblingStandIns::register();

        $this->app?->singleton(ContextContributors::class);
        $this->app?->register(AdapterServiceProvider::class);
    }

    /**
     * The adapter's provider registers the contributor under `sso`, and a
     * second registration under it is refused.
     *
     * @return void
     */
    public function testTheAdapterRegistersTheContributorOnce(): void
    {
        $contributors = app(ContextContributors::class);

        self::assertSame(['sso' => SsoContextContributor::class], $contributors->registered());

        $this->expectExceptionObject(new \LogicException('An authentication context contributor is already registered under [sso]: ' . SsoContextContributor::class . '.'));

        $contributors->register('sso', SsoContextContributor::class);
    }

    /**
     * For a session a sign-in through the package established, the contributor
     * answers every key of the captured provenance's projection without its
     * `sso.` prefix, read from the provider context authentication kept as
     * JSON.
     *
     * @return void
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     */
    public function testTheContributorProjectsTheSessionsProvenance(): void
    {
        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $linked       = $this->linkThroughFlow($provider, $connectionId, new IdentityReference('App\Models\User', 'person-1'));
        $signedIn     = $this->signInThroughFlow($provider, $connectionId, 'session-1');
        $stored       = $signedIn->provenance?->toArray();

        self::assertIsArray($stored);

        // Authentication keeps the provider context as JSON
        $kept = json_decode(json_encode($stored, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($kept);

        $subject = new ContributionSubject(new Provenance($connectionId, self::TENANT, linkId: $signedIn->linkId, providerContext: new ProviderContext($kept)));
        $keys    = $this->contributor()->contribute($subject);

        self::assertSame([
            'connection'                       => $connectionId,
            'tenant'                           => self::TENANT,
            'protocol'                         => 'oidc',
            'provider_auth_time'               => '2026-11-01T09:30:00.000000Z',
            'provider_amr'                     => [],
            'provider_acr'                     => null,
            'provider_authn_context_class_ref' => null,
            'link'                             => $linked->linkId,
            'link_provenance'                  => 'link_purpose',
            'provider_session_deadline'        => null,
            'session_not_after'                => null,
            'enforcement_version'              => null,
        ], $keys);
    }

    /**
     * A session no external provider established contributes no key.
     *
     * @return void
     */
    public function testASessionThePackageDidNotEstablishContributesNothing(): void
    {
        self::assertSame([], $this->contributor()->contribute(new ContributionSubject));
        self::assertSame([], $this->contributor()->contribute(new ContributionSubject(new Provenance('connection-1'))));
    }

    /**
     * The contributor registered under `sso`, resolved as authentication
     * resolves it.
     *
     * @return \Tests\Integration\Examples\IntegratingWithLaravelIam\SsoContextContributor
     */
    private function contributor(): SsoContextContributor
    {
        $contributor = app(app(ContextContributors::class)->registered()['sso']);

        self::assertInstanceOf(SsoContextContributor::class, $contributor);

        return $contributor;
    }
}
