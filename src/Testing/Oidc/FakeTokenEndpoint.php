<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;

/**
 * The fake OpenID provider's token endpoint (SSO-12.4, SSO-7.2), answering the
 * package's token requests on the fake fetcher as a strict provider would:
 *
 * - the client must authenticate by exactly the method it was registered with:
 *   `client_secret_basic` or `client_secret_post` with its secret, or
 *   `private_key_jwt` with a client assertion (RFC 7523) that verifies with its
 *   registered public key, under `typ` `JWT` and a `kid`, whose `iss` and `sub`
 *   are the client id, whose `aud` is this endpoint exactly, whose `jti`
 *   is new, and that has not expired and lives no longer than five minutes;
 *   otherwise `401` `invalid_client`;
 * - the form must be `grant_type=authorization_code` with a code this provider
 *   issued and nobody has used, the exact `redirect_uri` the authorisation
 *   request named, and the `code_verifier` whose S256 is its challenge;
 *   otherwise `400` `invalid_grant` (a used code stays used, as RFC 6749
 *   §4.1.2 asks);
 * - it answers `200` with the code's ID token, its access token, a refresh
 *   token the package must never keep, `token_type` `Bearer` and the scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeTokenEndpoint
{
    /** @var array<string, \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization> Each authorisation granted, by its code. */
    private array $authorizations = [];

    /** @var array<string, string> The codes already exchanged. */
    private array $used = [];

    /** @var array<string, string> The client assertion `jti`s already seen. */
    private array $assertions = [];

    /** @var array{client_id: string, method: string, secret: ?string, public_key: ?string} The registered client. */
    private array $client;

    /**
     * Constructor.
     *
     * @param  string  $url
     * @param  \Closure(): \Carbon\CarbonImmutable  $now
     * @param  string  $clientId
     */
    public function __construct(

        /** The endpoint's URL, a client assertion's `aud`. */
        private readonly string $url,

        /** The provider's clock. */
        private readonly \Closure $now,

        // The client registered until a test registers its own
        string $clientId,
    ) {
        $this->client = ['client_id' => $clientId, 'method' => 'client_secret_basic', 'secret' => 'fake-secret', 'public_key' => null];
    }

    /**
     * Answer a token request.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \LogicException
     */
    public function __invoke(FetchRequest $request): FetchResult
    {
        if (!$this->isAuthenticated($request)) {
            return self::json(401, ['error' => 'invalid_client']);
        }

        $authorization = $this->granted($request->form());

        if ($authorization === null) {
            return self::json(400, ['error' => 'invalid_grant', 'error_description' => 'The code is unknown, used, or its redirect_uri or code_verifier does not match.']);
        }

        return self::json(200, [
            'access_token'  => $authorization->accessToken,
            'token_type'    => 'Bearer',
            'expires_in'    => 300,
            'refresh_token' => 'fake-refresh-' . $authorization->code,
            'id_token'      => (string) $authorization->idToken,
            'scope'         => (string) $authorization->parameter('scope'),
        ]);
    }

    /**
     * Register the client the endpoint authenticates: its id, its method and
     * its secret or PEM public key.
     *
     * @param  string  $clientId
     * @param  string  $method
     * @param  ?string  $secret
     * @param  ?string  $publicKeyPem
     * @return void
     */
    public function register(string $clientId, string $method, #[\SensitiveParameter] ?string $secret = null, ?string $publicKeyPem = null): void
    {
        $this->client = ['client_id' => $clientId, 'method' => $method, 'secret' => $secret, 'public_key' => $publicKeyPem];
    }

    /**
     * Expect the authorisation's code.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $authorization
     * @return void
     */
    public function expect(FakeAuthorization $authorization): void
    {
        $this->authorizations[$authorization->code] = $authorization;
    }

    /**
     * The authorisation that issued the access token, or `null`.
     *
     * @param  string  $accessToken
     * @return ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization
     */
    public function issued(#[\SensitiveParameter] string $accessToken): ?FakeAuthorization
    {
        foreach ($this->authorizations as $code => $authorization) {
            if (isset($this->used[$code]) && hash_equals($authorization->accessToken, $accessToken)) {
                return $authorization;
            }
        }

        return null;
    }

    /**
     * A JSON response.
     *
     * @param  int  $status
     * @param  array<string, mixed>  $body
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    public static function json(int $status, array $body): FetchResult
    {
        return FetchResult::fetched($status, ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'], (string) json_encode($body, JSON_UNESCAPED_SLASHES));
    }

    /**
     * Whether the request is a token request authenticated by exactly the
     * registered client's method.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return bool
     */
    private function isAuthenticated(FetchRequest $request): bool
    {
        $credentials = $request->credentials;
        $method      = $this->client['method'];

        if ($request->purpose !== FetchPurpose::TOKEN || $credentials?->kind->value !== $method || $credentials->clientId !== $this->client['client_id']) {
            return false;
        }

        return $credentials->kind === CredentialKind::PRIVATE_KEY_JWT
            ? $this->isAssertion($credentials->secret())
            : hash_equals((string) $this->client['secret'], $credentials->secret());
    }

    /**
     * Whether the client assertion verifies with the registered key and carries
     * the claims RFC 7523 §3 asks for, with a `jti` never seen, which it then
     * records.
     *
     * @param  string  $assertion
     * @return bool
     */
    private function isAssertion(#[\SensitiveParameter] string $assertion): bool
    {
        $parts  = explode('.', $assertion);
        $header = json_decode(JwsSigner::decode($parts[0]), true);
        $claims = json_decode(JwsSigner::decode($parts[1] ?? ''), true);
        $read   = is_array($header) && is_array($claims);
        $signed = $read             && JwsSigner::verify($assertion, (string) $this->client['public_key']);
        $typed  = $signed           && ($header['typ'] ?? null) === 'JWT' && is_string($header['kid'] ?? null);
        $valid  = $typed            && $this->hasAssertionClaims($claims);
        $jti    = is_array($claims) ? ($claims['jti'] ?? null) : null;

        if ($valid && is_string($jti)) {
            $this->assertions[$jti] = $jti;
        }

        return $valid;
    }

    /**
     * Whether a client assertion's claims name this client and this endpoint,
     * carry a new `jti`, and have not expired nor live longer than five
     * minutes.
     *
     * @param  array<array-key, mixed>  $claims
     * @return bool
     */
    private function hasAssertionClaims(array $claims): bool
    {
        $client  = $this->client['client_id'];
        $jti     = $claims['jti'] ?? null;
        $expires = $claims['exp'] ?? null;
        $issued  = $claims['iat'] ?? null;
        $named   = ($claims['iss'] ?? null) === $client && ($claims['sub'] ?? null) === $client;
        $aimed   = ($claims['aud'] ?? null) === $this->url;
        $fresh   = is_string($jti)  && $jti !== '' && !isset($this->assertions[$jti]);
        $dated   = is_int($expires) && is_int($issued);
        $timely  = $dated           && $expires > ($this->now)()->getTimestamp() && $expires - $issued <= 300;

        return $named && $aimed && $fresh && $timely;
    }

    /**
     * The authorisation the form exchanges a code of, when the grant is
     * `authorization_code` for an unused code with its exact `redirect_uri` and
     * the verifier of its challenge.
     *
     * @param  array<string, string>  $form
     * @return ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization
     */
    private function granted(array $form): ?FakeAuthorization
    {
        $code          = $form['code']                ?? '';
        $authorization = $this->authorizations[$code] ?? null;

        if ($authorization === null) {
            return null;
        }

        $unused            = !isset($this->used[$code]);
        $this->used[$code] = $code;

        return $unused && $this->isGrantOf($authorization, $form) ? $authorization : null;
    }

    /**
     * Whether the form is an `authorization_code` grant of the authorisation's
     * code with its exact `redirect_uri` and the verifier of its challenge.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization  $authorization
     * @param  array<string, string>  $form
     * @return bool
     */
    private function isGrantOf(FakeAuthorization $authorization, array $form): bool
    {
        $type       = ($form['grant_type'] ?? null)   === 'authorization_code';
        $redirected = ($form['redirect_uri'] ?? null) === $authorization->parameter('redirect_uri');
        $challenge  = JwsSigner::encode(hash('sha256', $form['code_verifier'] ?? '', true));
        $proved     = $challenge === $authorization->parameter('code_challenge');

        return $type && $redirected && $proved;
    }
}
