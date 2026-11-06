<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\SamlMetadata;

use Illuminate\Http\RedirectResponse;
use Illuminate\Support\ViewErrorBag;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * What the examples of `docs/guides/saml-metadata.md` share (SSO-2.8,
 * SSO-12.5), on the shared example harness: the application's tenant, the
 * tenant's identity provider publishing its metadata at the guide's URL, the
 * tenant's SAML connection each example makes, the administrator acting, and
 * the administration endpoints under `admin/`, each run with its input as the
 * application's screen runs it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class SamlMetadataExampleTestCase extends ExampleTestCase
{
    /** @var string Where the provider publishes its metadata, as the guide fetches it. */
    protected const string METADATA_URL = 'https://idp.example.com/metadata.xml';

    /** @var string The provider's entity id, as the guide names it. */
    protected const string ENTITY_ID = 'https://idp.example.com/saml';

    /** @var string The provider's single sign-on URL. */
    protected const string SSO_URL = 'https://idp.example.com/saml/sso';

    /** @var \Tests\Integration\Examples\SamlMetadata\Tenant The tenant whose connection is managed. */
    protected Tenant $tenant;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The tenant's identity provider. */
    protected FakeSamlIdentityProvider $idp;

    /** @var \SineMacula\Laravel\Sso\Connections\ConnectionSummary The tenant's SAML connection, as each example makes it. */
    protected ConnectionSummary $connection;

    /**
     * Keep sessions in memory, for an endpoint that goes back with errors, and
     * make the tenant, its identity provider and its SAML connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('session.driver', 'array');

        $this->tenant = new Tenant(self::TENANT);
        $this->idp    = new FakeSamlIdentityProvider(self::ENTITY_ID);

        $this->connection = $this->makeConnection();
    }

    /**
     * Make the tenant's SAML connection, as the example needs it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     */
    abstract protected function makeConnection(): ConnectionSummary;

    /**
     * Serve the metadata from the guide's URL.
     *
     * @param  string  $xml
     * @return void
     */
    protected function serve(string $xml): void
    {
        $this->fetcher->respond(self::METADATA_URL, FetchResult::fetched(200, [], $xml));
    }

    /**
     * Save the guide's metadata URL on the connection, with any other settings
     * given, as an administrator would by hand.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    protected function withMetadataUrl(array $settings = []): ConnectionResult
    {
        return app(ConnectionService::class)->update(self::TENANT, $this->connection->id, [
            'settings' => ['metadata_url' => self::METADATA_URL, ...$settings],
        ], Clients::browser(), self::actor());
    }

    /**
     * The tenant's connection, or the one with the id given, as it is stored
     * now.
     *
     * @param  ?string  $connectionId
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     */
    protected function stored(?string $connectionId = null): ConnectionSummary
    {
        $stored = app(ConnectionService::class)->get(self::TENANT, $connectionId ?? $this->connection->id);

        static::assertNotNull($stored);

        return $stored;
    }

    /**
     * The fingerprint of each certificate the connection trusts for the use.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return list<?string>
     */
    protected function trustedFingerprints(KeyUse $use = KeyUse::IDP_SIGNING): array
    {
        $fingerprints = [];

        foreach (app(KeyService::class)->keys(self::TENANT, $this->connection->id) ?? [] as $key) {
            if ($key->use !== $use) {
                continue;
            }

            $fingerprints[] = $key->key->fingerprint;
        }

        return $fingerprints;
    }

    /**
     * The administrator, as the acting identity of each change.
     *
     * @return \SineMacula\Laravel\Sso\Administration\ActingIdentity
     */
    protected static function actor(): ActingIdentity
    {
        return new ActingIdentity('App\Models\User', '42');
    }

    /**
     * The administration endpoint of the name, given its input.
     *
     * @param  string  $endpoint
     * @param  array<string, mixed>  $input
     * @return mixed
     */
    protected static function atEndpoint(string $endpoint, array $input): mixed
    {
        return require __DIR__ . "/admin/{$endpoint}.php";
    }

    /**
     * The errors an endpoint went back with, by field.
     *
     * @param  mixed  $response
     * @return array<string, list<string>>
     */
    protected static function errors(mixed $response): array
    {
        static::assertInstanceOf(RedirectResponse::class, $response);

        $errors = $response->getSession()?->get('errors');

        static::assertInstanceOf(ViewErrorBag::class, $errors);

        /** @var array<string, list<string>> */
        return $errors->getBag('default')->toArray();
    }
}
