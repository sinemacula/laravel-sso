<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Oidc;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Fetching\FetchCredentials;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for the fake OpenID provider's token endpoint.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeTokenEndpoint::class)]
final class FakeTokenEndpointTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var string The endpoint's URL. */
    private const string URL = 'https://op.example.test/token';

    /** @var string The redirect URI the authorisation requests name. */
    private const string CALLBACK = 'https://sso.example.test/auth/sso/connections/c1/callback';

    /** @var string The PKCE verifier the authorisation requests are made with. */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The S256 challenge of the verifier (RFC 7636 appendix B). */
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * The client a code was granted to exchanges it.
     *
     * @return void
     */
    public function testExchangesACodeForTheClientItWasGrantedTo(): void
    {
        $endpoint = self::endpoint();

        $endpoint->expect(self::authorization('client-a'));

        $response = $endpoint(self::exchange('client-a', 'fake-secret'));

        self::assertSame([200, 'access-1'], [$response->statusCode, self::json($response)['access_token'] ?? null]);
    }

    /**
     * Another client, authenticated, is refused the code with `400`
     * `invalid_grant`, which burns it.
     *
     * @return void
     */
    public function testRefusesACodeGrantedToAnotherClient(): void
    {
        $endpoint = self::endpoint();

        $endpoint->expect(self::authorization('client-a'));
        $endpoint->register('client-b', 'client_secret_basic', 'secret-b');

        $refused = $endpoint(self::exchange('client-b', 'secret-b'));

        self::assertSame([400, 'invalid_grant'], [$refused->statusCode, self::json($refused)['error'] ?? null]);

        $endpoint->register('client-a', 'client_secret_basic', 'fake-secret');

        self::assertSame(400, $endpoint(self::exchange('client-a', 'fake-secret'))->statusCode);
    }

    /**
     * An endpoint whose registered client is `client-a`.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint
     */
    private static function endpoint(): FakeTokenEndpoint
    {
        return new FakeTokenEndpoint(self::URL, static fn (): CarbonImmutable => CarbonImmutable::createFromTimestampUTC(1900000000), 'client-a');
    }

    /**
     * The authorisation of a request the client made.
     *
     * @param  string  $clientId
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization
     */
    private static function authorization(string $clientId): FakeAuthorization
    {
        $parameters = ['client_id' => $clientId, 'redirect_uri' => self::CALLBACK, 'code_challenge' => self::CHALLENGE, 'scope' => 'openid'];

        return new FakeAuthorization($parameters, 'code-1', 'https://op.example.test', 'raw.id.token', 'access-1');
    }

    /**
     * The client's request to exchange the code.
     *
     * @param  string  $clientId
     * @param  string  $secret
     * @return \SineMacula\Laravel\Sso\Fetching\FetchRequest
     */
    private static function exchange(string $clientId, string $secret): FetchRequest
    {
        $form = ['grant_type' => 'authorization_code', 'code' => 'code-1', 'redirect_uri' => self::CALLBACK, 'code_verifier' => self::VERIFIER];

        return FetchRequest::token(self::URL, $form, FetchCredentials::clientSecretBasic($clientId, $secret));
    }

    /**
     * The JSON object a response's body holds.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @return array<array-key, mixed>
     */
    private static function json(FetchResult $response): array
    {
        $decoded = json_decode((string) $response->body(), true);

        return is_array($decoded) ? $decoded : [];
    }
}
