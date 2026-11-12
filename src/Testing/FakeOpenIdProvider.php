<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;

/**
 * An OpenID provider for tests, serving its endpoints on a `FakeFetcher`. It is
 * stateful, so keep it per test and never bind it as a singleton.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeOpenIdProvider
{
    /** @var string The issuer a provider has unless a test gives another. */
    public const string ISSUER = 'https://op.example.test';

    /** @var string The client id the provider expects unless a test registers another. */
    public const string CLIENT_ID = 'fake-client';

    /** @var string The client secret the provider expects unless a test registers another. */
    public const string CLIENT_SECRET = 'fake-secret';

    /** @var string The subject every ID token names unless a test changes it. */
    public const string SUBJECT = 'fake-subject';

    /** @var array<string, string> The path of each endpoint under the issuer. */
    private const array ENDPOINTS = ['authorization' => '/authorize', 'token' => '/token', 'userinfo' => '/userinfo', 'jwks' => '/jwks'];

    /** @var list<array<string, mixed>> The JWKS entries published, in order. */
    private array $published = [];

    /** @var string The algorithm ID tokens are signed by. */
    private string $algorithm = 'RS256';

    /** @var array<string, mixed> The test's changes to the discovery document; `null` removes a member. */
    private array $discoveryChanges = [];

    /** @var array<string, \Closure(\SineMacula\Laravel\Sso\Fetching\FetchRequest): \SineMacula\Laravel\Sso\Fetching\FetchResult|\SineMacula\Laravel\Sso\Fetching\FetchResult> Endpoint overrides, by name. */
    private array $responses = [];

    /** @var array<string, mixed> The UserInfo claims, beside the ID token's subject. */
    private array $userInfo = ['email' => 'person@example.test', 'email_verified' => true, 'name' => 'Fake Person'];

    /** @var string The client id ID tokens are issued to. */
    private string $clientId = self::CLIENT_ID;

    /** @var \SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint The token endpoint. */
    private FakeTokenEndpoint $tokens;

    /** @var \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key ID tokens are signed with. */
    private FakeSigningKey $signingKey;

    /**
     * Constructor.
     *
     * @param  string  $issuer
     * @param  ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $signingKey
     * @param  ?\SineMacula\Laravel\Sso\Contracts\Clock  $clock
     *
     * @throws \LogicException
     */
    public function __construct(

        /** The provider's issuer, exactly as its tokens and discovery document carry it. */
        public readonly string $issuer = self::ISSUER,

        // Not promoted: generated (RSA, `kid` `rsa-1`) when not given
        ?FakeSigningKey $signingKey = null,

        /** The package's clock, so tokens ignore Laravel's time travel; the current time by default. */
        private readonly ?Clock $clock = null,
    ) {
        $this->signingKey = $signingKey ?? FakeSigningKey::rsa();
        $this->tokens     = new FakeTokenEndpoint($this->endpoint('token'), fn (): CarbonImmutable => $this->now(), self::CLIENT_ID);

        $this->publish($this->signingKey);
    }

    /**
     * The key ID tokens are signed with now.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    public function signingKey(): FakeSigningKey
    {
        return $this->signingKey;
    }

    /**
     * The discovery document's URL under the issuer.
     *
     * @return string
     */
    public function discoveryUrl(): string
    {
        return rtrim($this->issuer, '/') . '/.well-known/openid-configuration';
    }

    /**
     * The URL of an endpoint: `authorization`, `token`, `userinfo` or `jwks`.
     *
     * @param  string  $name
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function endpoint(string $name): string
    {
        return rtrim($this->issuer, '/') . (self::ENDPOINTS[$name] ?? throw new \InvalidArgumentException(sprintf('The fake provider has no [%s] endpoint.', $name)));
    }

    /**
     * The discovery document, with the test's changes.
     *
     * @return array<string, mixed>
     */
    public function discovery(): array
    {
        $document = [
            'issuer'                                           => $this->issuer,
            'authorization_endpoint'                           => $this->endpoint('authorization'),
            'token_endpoint'                                   => $this->endpoint('token'),
            'userinfo_endpoint'                                => $this->endpoint('userinfo'),
            'jwks_uri'                                         => $this->endpoint('jwks'),
            'response_types_supported'                         => ['code'],
            'response_modes_supported'                         => ['query'],
            'grant_types_supported'                            => ['authorization_code'],
            'subject_types_supported'                          => ['public'],
            'id_token_signing_alg_values_supported'            => ['RS256', 'PS256', 'ES256'],
            'token_endpoint_auth_methods_supported'            => ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
            'token_endpoint_auth_signing_alg_values_supported' => ['PS256', 'ES256'],
            'code_challenge_methods_supported'                 => ['S256'],
            'scopes_supported'                                 => ['openid', 'email', 'profile'],
            'claims_supported'                                 => ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'name'],
            'authorization_response_iss_parameter_supported'   => true,
        ];

        return array_filter([...$document, ...$this->discoveryChanges], static fn (mixed $value): bool => $value !== null);
    }

    /**
     * Lay the members over the discovery document; a `null` removes one.
     *
     * @param  array<string, mixed>  $changes
     * @return $this
     */
    public function withDiscovery(array $changes): self
    {
        $this->discoveryChanges = [...$this->discoveryChanges, ...$changes];

        return $this;
    }

    /**
     * Publish the key in the JWKS.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  ?string  $alg
     * @param  ?string  $use
     * @param  array<string, mixed>  $extra
     * @return $this
     */
    public function publish(FakeSigningKey $key, ?string $alg = null, ?string $use = 'sig', array $extra = []): self
    {
        return $this->publishJwk($key->jwk($alg, $use, $extra));
    }

    /**
     * Publish the entry in the JWKS as is, however hostile.
     *
     * @param  array<string, mixed>  $jwk
     * @return $this
     */
    public function publishJwk(array $jwk): self
    {
        $this->published[] = $jwk;

        return $this;
    }

    /**
     * Remove every entry under the `kid`; `null` removes those without one.
     *
     * @param  ?string  $kid
     * @return $this
     */
    public function unpublish(?string $kid): self
    {
        $this->published = array_values(array_filter($this->published, static fn (array $jwk): bool => ($jwk['kid'] ?? null) !== $kid));

        return $this;
    }

    /**
     * The JWKS as it is published now.
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    public function jwks(): array
    {
        return ['keys' => $this->published];
    }

    /**
     * Sign ID tokens from now on with the key; this does not publish it.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @param  string  $algorithm
     * @return $this
     */
    public function signWith(FakeSigningKey $key, string $algorithm = 'RS256'): self
    {
        $this->signingKey = $key;
        $this->algorithm  = $algorithm;

        return $this;
    }

    /**
     * A valid ID token issued now, expiring in five minutes, with the claims
     * laid over it.
     *
     * @param  array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    public function idToken(array $claims = []): FakeIdToken
    {
        $now    = $this->now()->getTimestamp();
        $header = array_filter(['alg' => $this->algorithm, 'kid' => $this->signingKey->kid, 'typ' => 'JWT'], static fn (?string $value): bool => $value !== null);

        return new FakeIdToken($this->signingKey, $header, [
            'iss'       => $this->issuer,
            'sub'       => self::SUBJECT,
            'aud'       => $this->clientId,
            'iat'       => $now,
            'exp'       => $now + 300,
            'auth_time' => $now,
            ...$claims,
        ]);
    }

    /**
     * Grant the start's authorisation request a code whose ID token carries its
     * nonce and `at_hash`, changed by the tailor when given.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\StartResult|\SineMacula\Laravel\Sso\Protocols\Navigation|string  $url
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string)  $tailor
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization
     *
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    public function authorize(Navigation|StartResult|string $url, ?\Closure $tailor = null): FakeAuthorization
    {
        parse_str((string) parse_url(Navigations::url($url), PHP_URL_QUERY), $query);

        /** @var array<string, string> $parameters */
        $parameters  = array_filter($query, is_string(...));
        $accessToken = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $token       = $this->idToken(array_filter(['nonce' => $parameters['nonce'] ?? null], is_string(...)))->accessTokenHash($accessToken);

        $code          = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $authorization = new FakeAuthorization($parameters, $code, $this->issuer, $tailor === null ? $token : $tailor($token), $accessToken);

        $this->tokens->expect($authorization);

        return $authorization;
    }

    /**
     * Register the client, with its secret or its assertions' PEM public key.
     *
     * @param  string  $clientId
     * @param  string  $method
     * @param  ?string  $secret
     * @param  ?string  $publicKeyPem
     * @return $this
     */
    public function register(string $clientId, string $method, #[\SensitiveParameter] ?string $secret = null, ?string $publicKeyPem = null): self
    {
        $this->clientId = $clientId;

        $this->tokens->register($clientId, $method, $secret, $publicKeyPem);

        return $this;
    }

    /**
     * Answer UserInfo with the claims, beside the ID token's subject unless
     * they name their own `sub`.
     *
     * @param  array<string, mixed>  $claims
     * @return $this
     */
    public function withUserInfo(array $claims): self
    {
        $this->userInfo = $claims;

        return $this;
    }

    /**
     * Override an endpoint's answer; `null` restores its own behaviour.
     *
     * @param  string  $endpoint
     * @param  \Closure(\SineMacula\Laravel\Sso\Fetching\FetchRequest): \SineMacula\Laravel\Sso\Fetching\FetchResult|\SineMacula\Laravel\Sso\Fetching\FetchResult|null  $response
     * @return $this
     */
    public function respond(string $endpoint, \Closure|FetchResult|null $response): self
    {
        if ($response === null) {
            unset($this->responses[$endpoint]);
        } else {
            $this->responses[$endpoint] = $response;
        }

        return $this;
    }

    /**
     * Serve the endpoints on the fake fetcher, each read when fetched so key
     * changes show on the next fetch.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\FakeFetcher  $fetcher
     * @return $this
     */
    public function serve(FakeFetcher $fetcher): self
    {
        $fetcher->respond($this->discoveryUrl(), $this->answering('discovery', fn (): FetchResult => FakeTokenEndpoint::json(200, $this->discovery())));
        $fetcher->respond($this->endpoint('jwks'), $this->answering('jwks', fn (): FetchResult => FakeTokenEndpoint::json(200, $this->jwks())));
        $fetcher->respond($this->endpoint('token'), $this->answering('token', fn (FetchRequest $request): FetchResult => ($this->tokens)($request)));
        $fetcher->respond($this->endpoint('userinfo'), $this->answering('userinfo', $this->userInfoResponse(...)));

        return $this;
    }

    /**
     * An endpoint's override, read when fetched, or its own behaviour.
     *
     * @param  string  $endpoint
     * @param  \Closure(\SineMacula\Laravel\Sso\Fetching\FetchRequest): \SineMacula\Laravel\Sso\Fetching\FetchResult  $own
     * @return \Closure(\SineMacula\Laravel\Sso\Fetching\FetchRequest): \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    private function answering(string $endpoint, \Closure $own): \Closure
    {
        return function (FetchRequest $request) use ($endpoint, $own): FetchResult {

            $response = $this->responses[$endpoint] ?? $own;

            return $response instanceof FetchResult ? $response : $response($request);
        };
    }

    /**
     * The UserInfo claims for an issued access token, or `401` `invalid_token`.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    private function userInfoResponse(FetchRequest $request): FetchResult
    {
        $credentials   = $request->credentials;
        $authorization = $credentials?->kind === CredentialKind::ACCESS_TOKEN ? $this->tokens->issued($credentials->secret()) : null;

        if ($authorization === null) {
            return FakeTokenEndpoint::json(401, ['error' => 'invalid_token']);
        }

        $subject = $authorization->idToken instanceof FakeIdToken ? ($authorization->idToken->claims()['sub'] ?? self::SUBJECT) : self::SUBJECT;

        return FakeTokenEndpoint::json(200, ['sub' => $subject, ...$this->userInfo]);
    }

    /**
     * The provider's now.
     *
     * @return \Carbon\CarbonImmutable
     */
    private function now(): CarbonImmutable
    {
        return $this->clock?->now() ?? CarbonImmutable::now('UTC');
    }
}
