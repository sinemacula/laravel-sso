<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;

/**
 * An OpenID provider for tests (SSO-12.4), so an application tests its OIDC
 * flows without a network: its discovery document, its JWKS, signed ID tokens
 * with every knob a test needs (`Oidc\FakeIdToken`), and a token endpoint
 * (`Oidc\FakeTokenEndpoint`) and a UserInfo endpoint answering on the fake
 * fetcher. Every token is signed by hand with OpenSSL (`Oidc\JwsSigner`), never
 * by the package's JOSE library, and the hostile cases of the JOSE library
 * spike are `Oidc\HostileIdTokens`.
 *
 * `serve()` answers its discovery document, JWKS, token and UserInfo endpoints
 * on a `FakeFetcher`, each read when it is fetched, so a key published,
 * unpublished or replaced after a fetch is what the next fetch sees: rotation,
 * an addition and a removal under the same `kid`. `respond()` replaces what an
 * endpoint answers (an error, a timeout as `FetchResult::failed()`, a malformed
 * body). `authorize()` reads the URL the package's start sent the browser to,
 * as the provider's authorisation endpoint would, and grants it a code whose ID
 * token carries the request's nonce, an `at_hash` of its access token and any
 * change a test makes; the callback's query is the grant's `query()`, with the
 * RFC 9207 `iss`.
 *
 * Give a connection its `issuer()`, its `endpoint()`s (or import them from
 * `discoveryUrl()`), its `CLIENT_ID` and the client authentication `register()`
 * names. A second provider is an attacker: its keys are never in the
 * connection's JWKS.
 *
 * It keeps what a test configures and what its endpoints have answered, so it
 * is a test's own object, never bound as a singleton.
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

    /** @var array<string, mixed> What a test laid over the discovery document; `null` removes a member. */
    private array $discoveryChanges = [];

    /** @var array<string, \Closure(\SineMacula\Laravel\Sso\Fetching\FetchRequest): \SineMacula\Laravel\Sso\Fetching\FetchResult|\SineMacula\Laravel\Sso\Fetching\FetchResult> What an endpoint answers in place of its own behaviour, by its name. */
    private array $responses = [];

    /** @var array<string, mixed> The UserInfo claims, beside the subject of the access token's ID token. */
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

        // The key ID tokens are signed with, generated (RSA, `kid` `rsa-1`) and
        // published when not given
        ?FakeSigningKey $signingKey = null,

        /** The clock tokens are issued by; the current time when none is given. */
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
     * The discovery document's URL: the issuer, with any trailing `/` removed,
     * and `/.well-known/openid-configuration` (OpenID Connect Discovery §4).
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
     * The discovery document, with what a test laid over it.
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
     * Publish the key in the JWKS, with `alg` and `use` as given and any extra
     * members laid over its JWK.
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
     * Publish the entry in the JWKS as it is: an `oct` key, a private key,
     * anything a hostile JWKS holds.
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
     * Remove every entry published under the `kid`, or every entry without one
     * when it is `null`.
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
     * Sign ID tokens from now on with the key by the algorithm; the key is not
     * published by this, so a test publishes it or keeps it secret.
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
     * A valid ID token for the client, issued now: `iss`, `sub`, `aud`, `iat`,
     * `exp` five minutes on and `auth_time` now, with the claims given laid
     * over them, signed with the provider's key under its `kid`.
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
     * Grant the authorisation request the URL makes, as the authorisation
     * endpoint would: a code whose ID token carries the request's nonce and the
     * `at_hash` of its access token, changed by the tailor when one is given
     * (which answers a token, or a token's raw text).
     *
     * @param  string  $url
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string)  $tailor
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeAuthorization
     *
     * @throws \Random\RandomException
     */
    public function authorize(string $url, ?\Closure $tailor = null): FakeAuthorization
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

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
     * Register the client the token endpoint authenticates and ID tokens are
     * issued to: its id, its client authentication, and its secret or the PEM
     * public key its client assertions verify with.
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
     * Answer UserInfo with the claims given, beside the subject of the access
     * token's ID token unless they name their own `sub`.
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
     * Answer the endpoint (`discovery`, `jwks`, `token` or `userinfo`) with the
     * response, or with what the closure builds from the request; `null`
     * restores its own behaviour.
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
     * Answer the provider's discovery document, JWKS, token and UserInfo
     * endpoints on the fake fetcher, each read when it is fetched.
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
     * What answers an endpoint: the response a test gave it, read when it is
     * fetched, or its own behaviour.
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
     * The UserInfo response to a request carrying an access token the token
     * endpoint issued: the UserInfo claims with the subject of its ID token;
     * `401` `invalid_token` otherwise.
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
