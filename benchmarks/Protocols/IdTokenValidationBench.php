<?php

declare(strict_types = 1);

namespace Benchmarks\Protocols;

use Benchmarks\Support\BenchApplication;
use Carbon\CarbonImmutable;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\ParamProviders;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\FrozenClock;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Fixtures\Clients;

/**
 * `IdTokenValidator::validate()` on valid and rejected ID tokens.
 *
 * Every token names a stored key, so no revolution refetches the JWKS.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[BeforeMethods('setUp')]
#[Iterations(5)]
#[ParamProviders('provideVersions')]
#[Revs(100)]
#[Warmup(1)]
final class IdTokenValidationBench
{
    /** @var string The nonce the request stored the digest of. */
    private const string NONCE = 'the-request-nonce';

    /** @var string The access token the token endpoint answered. */
    private const string ACCESS_TOKEN = 'the-access-token';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Dq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var \SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator The validator. */
    private IdTokenValidator $validator; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the tokens are judged for. */
    private Connection $connection; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions The connection's options. */
    private OidcOptions $options; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\ConsumedRequest The request the tokens answer. */
    private ConsumedRequest $consumed; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse A token signed by RS256, valid. */
    private TokenResponse $validRs256; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse A token signed by ES256, valid. */
    private TokenResponse $validEs256; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse A token signed by another key under the provider's `kid`. */
    private TokenResponse $badSignature; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse A token issued to another client. */
    private TokenResponse $wrongAudience; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse A token past its `exp`. */
    private TokenResponse $expired; // @phpstan-ignore property.uninitialized

    /**
     * Store a connection holding the provider's JWKS and sign every token once.
     *
     * @return void
     */
    public function setUp(): void
    {
        $app      = BenchApplication::boot();
        $now      = CarbonImmutable::parse(BenchApplication::NOW);
        $rsa      = FakeSigningKey::rsa();
        $ec       = FakeSigningKey::ec();
        $provider = (new FakeOpenIdProvider(FakeOpenIdProvider::ISSUER, $rsa, new FrozenClock(BenchApplication::NOW)))->publish($ec);
        $jwks     = (string) json_encode($provider->jwks());

        $this->validator  = $app->make(IdTokenValidator::class);
        $this->connection = BenchApplication::connection([
            'protocol' => 'oidc',
            'jwks'     => ProviderKeySet::read($jwks, AlgorithmAllowList::of(OidcSettings::ID_TOKEN_ALGORITHMS), 65536, 50)?->toStored(),
            'settings' => [
                'issuer'                 => FakeOpenIdProvider::ISSUER,
                'authorization_endpoint' => $provider->endpoint('authorization'),
                'token_endpoint'         => $provider->endpoint('token'),
                'jwks_uri'               => $provider->endpoint('jwks'),
                'client_id'              => FakeOpenIdProvider::CLIENT_ID,
                'id_token_algorithms'    => ['RS256', 'ES256'],
            ],
        ]);

        $token     = $provider->idToken(['nonce' => self::NONCE]);
        $reference = RequestReference::fromString(self::REFERENCE);

        $this->options       = OidcOptions::of($this->connection);
        $this->consumed      = new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, $now, FakeOpenIdProvider::ISSUER, false, null, hash('sha256', self::NONCE));
        $this->validRs256    = new TokenResponse((string) $token, self::ACCESS_TOKEN);
        $this->validEs256    = new TokenResponse((string) $token->signedWith($ec, 'ES256'), self::ACCESS_TOKEN);
        $this->badSignature  = new TokenResponse((string) $token->signedWith(FakeSigningKey::rsa(), 'RS256'), self::ACCESS_TOKEN);
        $this->wrongAudience = new TokenResponse((string) $token->with('aud', 'another-client'), self::ACCESS_TOKEN);
        $this->expired       = new TokenResponse((string) $token->with('exp', $now->getTimestamp() - 3600), self::ACCESS_TOKEN);
    }

    /**
     * The versions of the packages these times depend on.
     *
     * @return array<string, array<string, string>>
     */
    public function provideVersions(): array
    {
        return BenchApplication::versions('web-token/jwt-library', 'laravel/framework');
    }

    /**
     * Validate a valid token signed by RS256.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
     */
    public function benchValidRs256(): IdTokenValidation
    {
        return $this->validate($this->validRs256);
    }

    /**
     * Validate a valid token signed by ES256.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
     */
    public function benchValidEs256(): IdTokenValidation
    {
        return $this->validate($this->validEs256);
    }

    /**
     * Reject a token signed by another key under the provider's `kid`.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
     */
    public function benchBadSignature(): IdTokenValidation
    {
        return $this->validate($this->badSignature);
    }

    /**
     * Reject a token issued to another client.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
     */
    public function benchWrongAudience(): IdTokenValidation
    {
        return $this->validate($this->wrongAudience);
    }

    /**
     * Reject a token past its `exp`.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
     */
    public function benchExpired(): IdTokenValidation
    {
        return $this->validate($this->expired);
    }

    /**
     * What the validator answers for the token response.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse  $tokens
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
     */
    private function validate(TokenResponse $tokens): IdTokenValidation
    {
        return $this->validator->validate($this->connection, $this->options, $tokens, $this->consumed, Clients::browser());
    }
}
