<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
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
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the validation of an ID token (SSO-7.3, SSO-7.4, SSO-5.10),
 * against a stored JWKS with the fake provider serving it: each reason pinned,
 * the fixed order of the checks pinned (a token failing two answers the first),
 * every boundary at, under and over, the refetch on an unknown `kid`, what a
 * validated token holds, and nothing of a token in a dump.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdTokenValidator::class)]
final class IdTokenValidatorTest extends TestCase
{
    use CapturesLogs, DumpsValues, UsesConnections;

    /** @var string The instant every token is issued and judged at. */
    private const string NOW = '2026-11-01T09:30:00Z';

    /** @var string The connection's issuer. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

    /** @var string The connection's client id. */
    private const string CLIENT = FakeOpenIdProvider::CLIENT_ID;

    /** @var string The nonce the request stored the digest of. */
    private const string NONCE = 'the-request-nonce';

    /** @var string The access token the token endpoint answered. */
    private const string ACCESS_TOKEN = 'the-access-token';

    /** @var string An audience the connection trusts. */
    private const string TRUSTED = 'https://api.example.test';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Dq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's key, made once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, made once. */
    private static ?FakeSigningKey $next = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's elliptic curve key, made once. */
    private static ?FakeSigningKey $ec = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey A key the provider never publishes, made once. */
    private static ?FakeSigningKey $attacker = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher a refetch goes through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the token is judged for. */
    private Connection $connection;

    /**
     * Bind a fixed clock and a fake fetcher serving the provider, create the
     * tables and the connection, and capture logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $clock          = new FixedClock(self::NOW);
        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(self::ISSUER, self::key(), $clock))->publish(self::ec())->serve($this->fetcher);

        $this->app?->instance(Clock::class, $clock);
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.oidc', true);
        config()->set('sso.clock.skew_seconds', 60);

        $this->usePackageTables();

        $this->connection = $this->connectionWith();

        $this->captureLogs();
    }

    /**
     * An honest token is validated: its issuer, its subject exactly and every
     * claim as it holds them, with nothing fetched or logged.
     *
     * @return void
     */
    public function testAnHonestTokenIsValidated(): void
    {
        $token      = $this->honest()->with('sub', " Person\t1 ")->with('groups', ['a', 'b']);
        $validation = $this->validate($token);

        self::assertTrue($validation->isValidated());
        self::assertNull($validation->reason);
        self::assertSame(self::ISSUER, $validation->token->issuer);
        self::assertSame(" Person\t1 ", $validation->token->subject());
        self::assertSame($token->claims(), $validation->token->claims());
        self::assertSame([], $this->jwksFetches());
        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * A validated token hands on a claim of a number too large for an integer
     * as a number, never its digits.
     *
     * @return void
     */
    public function testAValidatedTokenKeepsALargeNumberANumber(): void
    {
        $honest     = $this->honest();
        $json       = substr((string) json_encode($honest->claims(), JSON_UNESCAPED_SLASHES), 0, -1) . ',"employee":99999999999999999999}';
        $validation = $this->validate($honest->withPayloadJson($json));

        self::assertTrue($validation->isValidated());
        self::assertSame([...$honest->claims(), 'employee' => 1.0E+20], $validation->token->claims());
    }

    /**
     * Rows of `[tailor, reason]`: a token a check refuses.
     *
     * @return iterable<string, array{
     *     0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string),
     *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     * }>
     */
    public static function provideRefusals(): iterable
    {
        $invalid = FailureReason::ID_TOKEN_INVALID;
        $forged  = FailureReason::SIGNATURE_INVALID;
        $issuer  = FailureReason::ISSUER_MISMATCH;
        $aud     = FailureReason::AUDIENCE_MISMATCH;
        $expired = FailureReason::ASSERTION_EXPIRED;
        $nonce   = FailureReason::NONCE_MISMATCH;

        yield from [
            'not a token'          => [static fn (FakeIdToken $t): string => 'not-a-token', $invalid],
            'a JWE'                => [static fn (FakeIdToken $t): FakeIdToken => $t->asJwe(), $invalid],
            'alg none, unsigned'   => [static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('alg', 'none')->unsigned(), $invalid],
            'crit in the header'   => [static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('crit', ['exp']), $invalid],
            'alg none, signed'     => [static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('alg', 'none')->hmac('x'), $forged],
            'HMAC by a public key' => [static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('alg', 'HS256')->hmac(self::key()->publicKeyPem), $forged],
            'off the allow-list'   => [static fn (FakeIdToken $t): FakeIdToken => $t->signedWith(self::key(), 'PS512'), $forged],
            'another key'          => [static fn (FakeIdToken $t): FakeIdToken => $t->signedWith(self::attacker()->withKid('rsa-1'), 'RS256'), $forged],
            'a tampered payload'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', 'someone-else')->withSignatureOf((string) $t), $forged],

            'iss missing'             => [static fn (FakeIdToken $t): FakeIdToken => $t->without('iss'), $invalid],
            'iss an array'            => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', [self::ISSUER]), $invalid],
            'sub missing'             => [static fn (FakeIdToken $t): FakeIdToken => $t->without('sub'), $invalid],
            'sub an integer'          => [static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', 1), $invalid],
            'sub empty'               => [static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', ''), $invalid],
            'sub of 1025 bytes'       => [static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', str_repeat('a', 1025)), $invalid],
            'aud missing'             => [static fn (FakeIdToken $t): FakeIdToken => $t->without('aud'), $invalid],
            'aud an object'           => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', ['client' => self::CLIENT]), $invalid],
            'aud an object of a list' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', (object) ['0' => self::CLIENT]), $invalid],
            'aud a number'            => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', 1), $invalid],
            'aud an empty list'       => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', []), $invalid],
            'aud holding a number'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', [self::CLIENT, 1]), $invalid],
            'aud repeated'            => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', [self::CLIENT, self::CLIENT]), $invalid],
            'exp missing'             => [static fn (FakeIdToken $t): FakeIdToken => $t->without('exp'), $invalid],
            'exp a string'            => [static fn (FakeIdToken $t): FakeIdToken => $t->with('exp', (string) (self::now() + 300)), $invalid],
            'iat missing'             => [static fn (FakeIdToken $t): FakeIdToken => $t->without('iat'), $invalid],
            'nbf a string'            => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nbf', (string) self::now()), $invalid],
            'azp an array'            => [static fn (FakeIdToken $t): FakeIdToken => $t->with('azp', [self::CLIENT]), $invalid],
            'nonce an array'          => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', [self::NONCE]), $invalid],
            'auth_time a string'      => [static fn (FakeIdToken $t): FakeIdToken => $t->with('auth_time', (string) self::now()), $invalid],
            'at_hash an array'        => [static fn (FakeIdToken $t): FakeIdToken => $t->with('at_hash', ['x']), $invalid],
            'amr a string'            => [static fn (FakeIdToken $t): FakeIdToken => $t->with('amr', 'pwd'), $invalid],
            'amr of 33 entries'       => [static fn (FakeIdToken $t): FakeIdToken => $t->with('amr', array_fill(0, 33, 'pwd')), $invalid],

            'iss another'          => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', 'https://other.example.test'), $issuer],
            'iss a trailing slash' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', self::ISSUER . '/'), $issuer],
            'iss of another case'  => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', strtoupper(self::ISSUER)), $issuer],
            'iss empty'            => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', ''), $issuer],

            'aud another'           => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', 'another-client'), $aud],
            'aud with an untrusted' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', [self::CLIENT, 'untrusted'])->with('azp', self::CLIENT), $aud],
            'aud trusted, no azp'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', [self::CLIENT, self::TRUSTED]), $aud],
            'azp another client'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('azp', 'another-client'), $aud],
            'aud of another case'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', strtoupper(self::CLIENT)), $aud],
            'aud with whitespace'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', self::CLIENT . ' '), $aud],
            'aud only trusted'      => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', self::TRUSTED), $aud],

            'exp at now less the skew'  => [static fn (FakeIdToken $t): FakeIdToken => $t->with('exp', self::now() - 60), $expired],
            'exp past now and the skew' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('exp', self::now() - 61), $expired],
            'iat ahead past the skew'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iat', self::now() + 61), $expired],
            'iat older than its age'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iat', self::now() - 361), $expired],
            'nbf ahead past the skew'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nbf', self::now() + 61), $expired],

            'nonce missing'         => [static fn (FakeIdToken $t): FakeIdToken => $t->without('nonce'), $nonce],
            'nonce another'         => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', 'another-nonce'), $nonce],
            'nonce empty'           => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', ''), $nonce],
            'nonce of another case' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', strtoupper(self::NONCE)), $nonce],
            'nonce of the digest'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', hash('sha256', self::NONCE)), $nonce],

            'auth_time past now and the skew' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('auth_time', self::now() + 61), $expired],

            'at_hash wrong'            => [static fn (FakeIdToken $t): FakeIdToken => $t->with('at_hash', 'wrong'), FailureReason::AT_HASH_MISMATCH],
            'at_hash of another token' => [static fn (FakeIdToken $t): FakeIdToken => $t->accessTokenHash('another-access-token'), FailureReason::AT_HASH_MISMATCH],
        ];
    }

    /**
     * Each check refuses with its own reason, with no JWKS fetched.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): (\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string)  $tailor
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testEachCheckRefusesWithItsReason(\Closure $tailor, FailureReason $reason): void
    {
        $validation = $this->validate($tailor($this->honest()));

        self::assertFalse($validation->isValidated());
        self::assertNull($validation->token);
        self::assertSame($reason, $validation->reason);
        self::assertSame([], $this->jwksFetches());
        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * Rows of `[tailor]`: a token at or just under a boundary, which passes.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken}>
     */
    public static function provideAcceptedTokens(): iterable
    {
        yield from [
            'at_hash absent'             => [static fn (FakeIdToken $t): FakeIdToken => $t->without('at_hash')],
            'at_hash right'              => [static fn (FakeIdToken $t): FakeIdToken => $t->accessTokenHash(self::ACCESS_TOKEN)],
            'auth_time absent'           => [static fn (FakeIdToken $t): FakeIdToken => $t->without('auth_time')],
            'auth_time old, no max_age'  => [static fn (FakeIdToken $t): FakeIdToken => $t->with('auth_time', 1)],
            'auth_time at now and skew'  => [static fn (FakeIdToken $t): FakeIdToken => $t->with('auth_time', self::now() + 60)],
            'exp just inside the skew'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('exp', self::now() - 59)],
            'iat at now and the skew'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iat', self::now() + 60)],
            'iat at its age and skew'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iat', self::now() - 360)],
            'nbf at now and the skew'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nbf', self::now() + 60)],
            'azp the client'             => [static fn (FakeIdToken $t): FakeIdToken => $t->with('azp', self::CLIENT)],
            'aud a list of the client'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', [self::CLIENT])],
            'aud with a trusted and azp' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', [self::CLIENT, self::TRUSTED])->with('azp', self::CLIENT)],
            'sub at its cap'             => [static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', str_repeat('a', 1024))],
            'every optional claim'       => [
                static fn (FakeIdToken $t): FakeIdToken => $t
                    ->with('acr', 'mfa')
                    ->with('sid', 'session')
                    ->with('amr', ['pwd'])
                    ->with('email', 'a@example.test')
                    ->with('email_verified', true),
            ],
        ];
    }

    /**
     * A token at or just under each boundary is validated.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @return void
     */
    #[DataProvider('provideAcceptedTokens')]
    public function testATokenWithinTheBoundariesIsValidated(\Closure $tailor): void
    {
        $this->connection = $this->connectionWith(['trusted_audiences' => [self::TRUSTED]]);

        self::assertTrue($this->validate($tailor($this->honest()))->isValidated());
    }

    /**
     * Rows of `[tailor, reason]`: a token failing two checks, the earlier
     * first.
     *
     * @return iterable<string, array{
     *     0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken,
     *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     * }>
     */
    public static function provideOrder(): iterable
    {
        yield from [
            'unreadable, not the key' => [
                static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('crit', ['exp'])->withHeader('alg', 'HS256')->hmac('x'),
                FailureReason::ID_TOKEN_INVALID,
            ],
            'the key, not the types' => [
                static fn (FakeIdToken $t): FakeIdToken => $t->withHeader('alg', 'HS256')->with('sub', 1)->hmac('x'),
                FailureReason::SIGNATURE_INVALID,
            ],
            'the signature, not the types' => [
                static fn (FakeIdToken $t): FakeIdToken => $t->signedWith(self::attacker()->withKid('rsa-1'), 'RS256')->with('sub', 1),
                FailureReason::SIGNATURE_INVALID,
            ],
            'the types, not the issuer' => [
                static fn (FakeIdToken $t): FakeIdToken => $t->with('sub', 1)->with('iss', 'https://other.example.test'),
                FailureReason::ID_TOKEN_INVALID,
            ],
            'the issuer, not the audience' => [
                static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', 'https://other.example.test')->with('aud', 'another-client'),
                FailureReason::ISSUER_MISMATCH,
            ],
            'the audience, not the times' => [
                static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', 'another-client')->with('exp', self::now() - 100),
                FailureReason::AUDIENCE_MISMATCH,
            ],
            'the times, not the nonce' => [
                static fn (FakeIdToken $t): FakeIdToken => $t->with('exp', self::now() - 100)->with('nonce', 'another-nonce'),
                FailureReason::ASSERTION_EXPIRED,
            ],
            'the nonce, not auth_time' => [
                static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', 'another-nonce')->with('auth_time', self::now() + 100),
                FailureReason::NONCE_MISMATCH,
            ],
            'auth_time, not at_hash' => [
                static fn (FakeIdToken $t): FakeIdToken => $t->with('auth_time', self::now() + 100)->with('at_hash', 'wrong'),
                FailureReason::ASSERTION_EXPIRED,
            ],
        ];
    }

    /**
     * The checks run in their fixed order, the first failure answering.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideOrder')]
    public function testTheFirstFailureAnswers(\Closure $tailor, FailureReason $reason): void
    {
        self::assertSame($reason, $this->validate($tailor($this->honest()))->reason);
    }

    /**
     * The token must be of the issuer the request pinned as well as the
     * connection's: a connection's issuer changed since the start, or a request
     * that pinned none, is `issuer_mismatch`.
     *
     * @return void
     */
    public function testTheIssuerMustBeTheOneTheRequestPinned(): void
    {
        $token = $this->honest();

        self::assertTrue($this->validate($token, $this->consumed())->isValidated());
        self::assertSame(FailureReason::ISSUER_MISMATCH, $this->validate($token, $this->consumed(expectedIssuer: 'https://other.example.test'))->reason);
        self::assertSame(FailureReason::ISSUER_MISMATCH, $this->validate($token, $this->consumed(expectedIssuer: null))->reason);
    }

    /**
     * A nonce is at most 512 bytes, however it was stored.
     *
     * @return void
     */
    public function testANonceIsHeldToItsLength(): void
    {
        foreach ([1 => true, 511 => true, 512 => true, 513 => false] as $bytes => $accepted) {

            $nonce      = str_repeat('n', $bytes);
            $validation = $this->validate($this->honest()->with('nonce', $nonce), $this->consumed($nonce));

            self::assertSame($accepted ? null : FailureReason::NONCE_MISMATCH, $validation->reason, (string) $bytes);
        }
    }

    /**
     * A request that stored no nonce admits no token.
     *
     * @return void
     */
    public function testARequestWithNoNonceAdmitsNoToken(): void
    {
        $consumed = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(self::REFERENCE), self::instant(), self::ISSUER);

        self::assertSame(FailureReason::NONCE_MISMATCH, $this->validate($this->honest(), $consumed)->reason);
    }

    /**
     * Rows of `[auth_time offset, reason]`: `auth_time` around `max_age` 300.
     *
     * @return iterable<string, array{0: ?int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideMaxAges(): iterable
    {
        yield from [
            'now'                    => [0, null],
            'under max_age and skew' => [-359, null],
            'at max_age and skew'    => [-360, null],
            'over max_age and skew'  => [-361, FailureReason::AUTHENTICATION_EXPIRED],
            'absent'                 => [null, FailureReason::ID_TOKEN_INVALID],
            'past now and the skew'  => [61, FailureReason::ASSERTION_EXPIRED],
        ];
    }

    /**
     * A connection's `max_age` needs `auth_time`, within it and the skew.
     *
     * @param  ?int  $offset
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideMaxAges')]
    public function testAConnectionsMaxAgeIsHeld(?int $offset, ?FailureReason $reason): void
    {
        $this->connection = $this->connectionWith(['max_age' => 300]);

        $token = $offset === null ? $this->honest()->without('auth_time') : $this->honest()->with('auth_time', self::now() + $offset);

        self::assertSame($reason, $this->validate($token)->reason);
    }

    /**
     * Rows of `[auth_time offset, started offset, reason]`: `auth_time` around
     * a reauthentication's `max_age` of 0 and its start, the connection's own
     * `max_age` of a week left unread.
     *
     * @return iterable<string, array{0: ?int, 1: int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideReauthentications(): iterable
    {
        $expired = FailureReason::AUTHENTICATION_EXPIRED;

        yield from [
            'now'                             => [0, 0, null],
            'under the skew'                  => [-59, 0, null],
            'at the skew'                     => [-60, 0, null],
            'over the skew'                   => [-61, 0, $expired],
            'at the skew, started long ago'   => [-60, -120, null],
            'fresh, the callback slow'        => [-120, -120, null],
            'an hour on from a fresh start'   => [-3600, -3600, null],
            'over the skew, started long ago' => [-181, -120, $expired],
            'absent'                          => [null, 0, FailureReason::ID_TOKEN_INVALID],
            'under the start and skew'        => [-40, 19, null],
            'at the start and skew'           => [-41, 19, null],
            'over the start and skew'         => [-42, 19, $expired],
            'past now and the skew'           => [61, 0, FailureReason::ASSERTION_EXPIRED],
        ];
    }

    /**
     * A `reauthenticate` needs `auth_time` and is refused before its own start
     * less the skew, whatever the connection's `max_age`, and however long ago
     * that start was: it is never judged against when the callback runs.
     *
     * @param  ?int  $offset
     * @param  int  $started
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideReauthentications')]
    public function testAReauthenticationIsHeldToItsStart(?int $offset, int $started, ?FailureReason $reason): void
    {
        $this->connection = $this->connectionWith(['max_age' => 604800]);

        $token    = $offset === null ? $this->honest()->without('auth_time') : $this->honest()->with('auth_time', self::now() + $offset);
        $consumed = $this->consumed(purpose: Purpose::REAUTHENTICATE, startedAt: self::instant()->addSeconds($started));

        self::assertSame($reason, $this->validate($token, $consumed)->reason);
    }

    /**
     * A purpose other than `reauthenticate` is not held to its start, nor to a
     * `max_age` of 0.
     *
     * @return void
     */
    public function testOtherPurposesAreNotHeldToTheirStart(): void
    {
        $token = $this->honest()->with('auth_time', self::now() - 1000);

        foreach ([Purpose::SIGN_IN, Purpose::LINK] as $purpose) {
            self::assertNull($this->validate($token, $this->consumed(purpose: $purpose))->reason, $purpose->value);
        }
    }

    /**
     * Rows of `[auth_time offset, started offset, reason]`: a connection's
     * `max_age` of 0, around the request's start.
     *
     * @return iterable<string, array{0: ?int, 1: int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideAfreshAuthentications(): iterable
    {
        $expired = FailureReason::AUTHENTICATION_EXPIRED;

        yield from [
            'fresh'                       => [0, 0, null],
            'fresh, the callback slow'    => [-3600, -3600, null],
            'at the start and skew, slow' => [-3660, -3600, null],
            'before the start and skew'   => [-3661, -3600, $expired],
            'absent'                      => [null, -3600, FailureReason::ID_TOKEN_INVALID],
            'past now and the skew'       => [61, -3600, FailureReason::ASSERTION_EXPIRED],
        ];
    }

    /**
     * A connection's `max_age` of 0 is held to the request, whatever the flow,
     * never to how long the callback took.
     *
     * @param  ?int  $offset
     * @param  int  $started
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideAfreshAuthentications')]
    public function testAMaxAgeOfZeroIsHeldToTheRequest(?int $offset, int $started, ?FailureReason $reason): void
    {
        $this->connection = $this->connectionWith(['max_age' => 0]);

        $token    = $offset === null ? $this->honest()->without('auth_time') : $this->honest()->with('auth_time', self::now() + $offset);
        $consumed = $this->consumed(startedAt: self::instant()->addSeconds($started));

        self::assertSame($reason, $this->validate($token, $consumed)->reason);
    }

    /**
     * A reauthentication under a connection's positive `max_age` is held to
     * both: its start, and the configured age, which is measured from now.
     *
     * @return void
     */
    public function testAReauthenticationIsStillHeldToAConfiguredAge(): void
    {
        $this->connection = $this->connectionWith(['max_age' => 300]);

        $consumed = $this->consumed(purpose: Purpose::REAUTHENTICATE, startedAt: self::instant()->subSeconds(3600));

        self::assertNull($this->validate($this->honest()->with('auth_time', self::now() - 360), $consumed)->reason);
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, $this->validate($this->honest()->with('auth_time', self::now() - 361), $consumed)->reason);
    }

    /**
     * Rows of `[tailor]`: a token with an unknown `kid` already disqualified on
     * its unverified claims.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken}>
     */
    public static function provideDisqualifiedTokens(): iterable
    {
        yield from [
            'another issuer'   => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iss', 'https://other.example.test')],
            'another audience' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', 'another-client')],
            'another nonce'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nonce', 'another-nonce')],
            'no nonce'         => [static fn (FakeIdToken $t): FakeIdToken => $t->without('nonce')],
            'expired'          => [static fn (FakeIdToken $t): FakeIdToken => $t->with('exp', self::now() - 61)],
            'too old'          => [static fn (FakeIdToken $t): FakeIdToken => $t->with('iat', self::now() - 361)],
            'not yet valid'    => [static fn (FakeIdToken $t): FakeIdToken => $t->with('nbf', self::now() + 61)],
            'exp a string'     => [static fn (FakeIdToken $t): FakeIdToken => $t->with('exp', (string) (self::now() + 300))],
            'sub missing'      => [static fn (FakeIdToken $t): FakeIdToken => $t->without('sub')],
            'aud a number'     => [static fn (FakeIdToken $t): FakeIdToken => $t->with('aud', 1)],
            'amr a string'     => [static fn (FakeIdToken $t): FakeIdToken => $t->with('amr', 'pwd')],
            'an at_hash wrong' => [static fn (FakeIdToken $t): FakeIdToken => $t->with('at_hash', 'wrong')],
        ];
    }

    /**
     * A token already disqualified on its unverified claims fetches nothing and
     * leaves the shared cooldown unclaimed. Its answer is the one any token no
     * held key verifies gets, so it says nothing of its claims.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @return void
     */
    #[DataProvider('provideDisqualifiedTokens')]
    public function testADisqualifiedTokenSpendsNoCooldown(\Closure $tailor): void
    {
        $validation = $this->validate($tailor($this->honest()->withHeader('kid', 'unknown-1')));
        $connection = $this->connection->refresh();

        self::assertSame(FailureReason::SIGNATURE_INVALID, $validation->reason);
        self::assertSame([], $this->jwksFetches());
        self::assertNull($connection->jwks_refetch_at);
        self::assertNull($connection->jwks_claim_token);
        self::assertSame(0, $connection->jwks_refetch_suppressed);
    }

    /**
     * A token that passes the prechecks on its unverified claims spends the
     * cooldown, and still has to verify: nothing about its claims stands in for
     * its signature, whatever key it names.
     *
     * @return void
     */
    public function testATokenPassingThePrechecksMustStillVerify(): void
    {
        $validation = $this->validate($this->honest()->signedWith(self::attacker()->withKid('unknown-1'), 'RS256'));

        self::assertSame(FailureReason::SIGNATURE_INVALID, $validation->reason);
        self::assertCount(1, $this->jwksFetches());
        self::assertNotNull($this->connection->refresh()->jwks_refetch_at);
    }

    /**
     * A token signed by a key the connection already holds is refused for its
     * claims by name, as ever: the prechecks only ever stop a refetch.
     *
     * @return void
     */
    public function testThePrechecksNeverChangeTheAnswerForAKnownKey(): void
    {
        self::assertSame(FailureReason::ISSUER_MISMATCH, $this->validate($this->honest()->with('iss', 'https://other.example.test'))->reason);
        self::assertSame([], $this->jwksFetches());
    }

    /**
     * Rows of `[algorithm, hash]`: `at_hash` by each size of algorithm.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideHashSizes(): iterable
    {
        yield from [
            'RS256' => ['RS256', 'sha256'],
            'RS384' => ['RS384', 'sha384'],
            'RS512' => ['RS512', 'sha512'],
            'PS384' => ['PS384', 'sha384'],
            'ES256' => ['ES256', 'sha256'],
        ];
    }

    /**
     * `at_hash` is the hash of the token's own algorithm size, and another
     * size's is refused.
     *
     * @param  string  $algorithm
     * @param  string  $hash
     * @return void
     */
    #[DataProvider('provideHashSizes')]
    public function testAtHashFollowsTheAlgorithmsSize(string $algorithm, string $hash): void
    {
        $this->connection = $this->connectionWith(['id_token_algorithms' => OidcSettings::ID_TOKEN_ALGORITHMS]);

        $key   = str_starts_with($algorithm, 'ES') ? self::ec() : self::key();
        $token = $this->honest()->signedWith($key, $algorithm);
        $other = $hash === 'sha256' ? 'sha512' : 'sha256';

        self::assertNull($this->validate($token->with('at_hash', self::atHash($hash)))->reason);
        self::assertSame(FailureReason::AT_HASH_MISMATCH, $this->validate($token->with('at_hash', self::atHash($other)))->reason);
    }

    /**
     * The size cap is the configured one: a token at it is read, and one a byte
     * over it is not.
     *
     * @return void
     */
    public function testTheSizeCapIsHeld(): void
    {
        $token = (string) $this->honest()->with('padding', str_repeat('a', 2048));

        config()->set('sso.oidc.max_id_token_bytes', strlen($token));

        self::assertTrue($this->validate($token)->isValidated());

        config()->set('sso.oidc.max_id_token_bytes', strlen($token) - 1);

        self::assertSame(FailureReason::ID_TOKEN_INVALID, $this->validate($token)->reason);
    }

    /**
     * `iat`'s maximum age is the configured one.
     *
     * @return void
     */
    public function testTheMaximumAgeIsTheConfiguredOne(): void
    {
        config()->set('sso.oidc.id_token_max_age_seconds', 60);

        self::assertNull($this->validate($this->honest()->with('iat', self::now() - 120))->reason);
        self::assertSame(FailureReason::ASSERTION_EXPIRED, $this->validate($this->honest()->with('iat', self::now() - 121))->reason);
    }

    /**
     * The skew is the configured one, read on each call.
     *
     * @return void
     */
    public function testTheSkewIsReadOnEachCall(): void
    {
        $token = $this->honest()->with('iat', self::now() + 30)->with('auth_time', self::now() + 30);

        self::assertNull($this->validate($token)->reason);

        config()->set('sso.clock.skew_seconds', 0);

        self::assertSame(FailureReason::ASSERTION_EXPIRED, $this->validate($token)->reason);

        config()->set('sso.clock.skew_seconds', 60);

        self::assertNull($this->validate($token)->reason);
    }

    /**
     * An unknown `kid` refetches the JWKS once, and the token signed with the
     * key it brought is validated.
     *
     * @return void
     */
    public function testAnUnknownKidRefetchesOnce(): void
    {
        $this->provider->publish(self::next());

        $validation = $this->validate($this->honest()->signedWith(self::next(), 'RS256'));

        self::assertTrue($validation->isValidated());
        self::assertCount(1, $this->jwksFetches());
    }

    /**
     * An unknown `kid` the refetch did not bring is `signature_invalid`, and
     * another within the cooldown fetches nothing.
     *
     * @return void
     */
    public function testAKidTheRefetchDidNotBringIsRefused(): void
    {
        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->validate($this->honest()->withHeader('kid', 'unknown-1'))->reason);
        self::assertCount(1, $this->jwksFetches());

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->validate($this->honest()->withHeader('kid', 'unknown-2'))->reason);
        self::assertCount(1, $this->jwksFetches());
    }

    /**
     * A refetch a trust change overtook is the connection's refusal, not the
     * token's, and nothing is verified.
     *
     * @return void
     */
    public function testARefetchOvertakenByATrustChangeIsTheConnections(): void
    {
        $connection = $this->connection;

        $this->provider->respond('jwks', function (FetchRequest $request) use ($connection): FetchResult {
            unset($request);

            Connection::query()->whereKey($connection->id)->update(['trust_version' => 5]);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->validate($this->honest()->withHeader('kid', 'unknown-1'))->reason);
    }

    /**
     * A token with no `kid` is checked with the only admissible key, with
     * nothing fetched; among two it is refused, still with nothing fetched; and
     * an unknown `kid` never falls back to a key with none.
     *
     * @return void
     */
    public function testTheMissingKidRule(): void
    {
        $token = $this->honest()->withoutHeader('kid');

        self::assertTrue($this->validate($token)->isValidated());

        $this->connection = $this->connectionWith([], [self::key(), self::next()]);

        $amongTwo = $this->validate($token);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $amongTwo->reason);
        self::assertSame([], $this->jwksFetches());

        $this->connection = $this->connectionWith([], [self::key()->withKid(null)]);

        $refused = $this->validate($this->honest()->withHeader('kid', '0'));

        self::assertSame(FailureReason::SIGNATURE_INVALID, $refused->reason);
        self::assertCount(1, $this->jwksFetches());
    }

    /**
     * An allow-list decides per connection, read afresh: a token of an
     * algorithm the connection has since left off is refused with nothing
     * fetched.
     *
     * @return void
     */
    public function testTheAllowListIsTheConnections(): void
    {
        $token = $this->honest();

        self::assertTrue($this->validate($token)->isValidated());

        $this->connection = $this->connectionWith(['id_token_algorithms' => ['ES256']]);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->validate($token)->reason);
        self::assertSame([], $this->jwksFetches());
    }

    /**
     * A validation's every dump and its JSON show the issuer and the names of
     * the claims alone, never the token, the subject or a claim's value.
     *
     * @return void
     */
    public function testNothingOfTheTokenIsInADump(): void
    {
        $token      = $this->honest()->with('sub', 'the-subject-never-shown');
        $validation = $this->validate($token);
        $text       = [...array_values(self::dumps($validation)), (string) json_encode($validation)];

        foreach ($text as $dump) {
            foreach ([(string) $token, ...explode('.', (string) $token), 'the-subject-never-shown', self::NONCE, self::ACCESS_TOKEN] as $needle) {
                self::assertStringNotContainsString($needle, $dump);
            }
        }
    }

    /**
     * An honest token for the provider, carrying the request's nonce.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private function honest(): FakeIdToken
    {
        return $this->provider->idToken(['nonce' => self::NONCE]);
    }

    /**
     * The validation of the token for the connection and the request.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string  $token
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation
     */
    private function validate(FakeIdToken|string $token, ?ConsumedRequest $consumed = null): IdTokenValidation
    {
        return app(IdTokenValidator::class)->validate(
            $this->connection,
            OidcOptions::of($this->connection),
            new TokenResponse((string) $token, self::ACCESS_TOKEN),
            $consumed ?? $this->consumed(),
            Clients::browser(),
        );
    }

    /**
     * The request the token answers.
     *
     * @param  string  $nonce
     * @param  ?string  $expectedIssuer
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\Carbon\CarbonImmutable  $startedAt
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     */
    private function consumed(
        string $nonce = self::NONCE,
        ?string $expectedIssuer = self::ISSUER,
        Purpose $purpose = Purpose::SIGN_IN,
        ?CarbonImmutable $startedAt = null,
    ): ConsumedRequest {
        $reference = RequestReference::fromString(self::REFERENCE);

        return new ConsumedRequest($purpose, 'web', $reference, $startedAt ?? self::instant(), $expectedIssuer, false, null, hash('sha256', $nonce));
    }

    /**
     * A connection of the provider storing the keys given, or its key.
     *
     * @param  array<string, mixed>  $settings
     * @param  ?list<\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey>  $keys
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connectionWith(array $settings = [], ?array $keys = null): Connection
    {
        $jwks = (string) json_encode(['keys' => array_map(static fn (FakeSigningKey $key): array => $key->jwk(), $keys ?? [self::key(), self::ec()])]);

        return $this->makeConnection([
            'enabled'  => true,
            'jwks'     => ProviderKeySet::read($jwks, AlgorithmAllowList::of(OidcSettings::ID_TOKEN_ALGORITHMS), 65536, 50)?->toStored(),
            'settings' => [
                'issuer'                 => self::ISSUER,
                'authorization_endpoint' => self::ISSUER . '/authorize',
                'token_endpoint'         => self::ISSUER . '/token',
                'jwks_uri'               => self::ISSUER . '/jwks',
                'client_id'              => self::CLIENT,
                'id_token_algorithms'    => ['RS256', 'PS256', 'ES256'],
                ...$settings,
            ],
        ]);
    }

    /**
     * The JWKS requests made, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Fetching\FetchRequest>
     */
    private function jwksFetches(): array
    {
        return array_values(array_filter($this->fetcher->requests(), static fn (FetchRequest $request): bool => $request->purpose === FetchPurpose::JWKS));
    }

    /**
     * The `at_hash` of the access token by the hash, computed apart from the
     * package.
     *
     * @param  string  $hash
     * @return string
     */
    private static function atHash(string $hash): string
    {
        $digest = hash($hash, self::ACCESS_TOKEN, true);

        return rtrim(strtr(base64_encode(substr($digest, 0, intdiv(strlen($digest), 2))), '+/', '-_'), '=');
    }

    /**
     * The instant every token is judged at.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function instant(): CarbonImmutable
    {
        return CarbonImmutable::parse(self::NOW);
    }

    /**
     * The instant every token is judged at, in seconds since the epoch.
     *
     * @return int
     */
    private static function now(): int
    {
        return self::instant()->getTimestamp();
    }

    /**
     * The provider's key, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa('rsa-1');
    }

    /**
     * The provider's next key, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function next(): FakeSigningKey
    {
        return self::$next ??= FakeSigningKey::rsa('rsa-2');
    }

    /**
     * The provider's elliptic curve key, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function ec(): FakeSigningKey
    {
        return self::$ec ??= FakeSigningKey::ec('ec-1');
    }

    /**
     * A key the provider never publishes, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function attacker(): FakeSigningKey
    {
        return self::$attacker ??= FakeSigningKey::rsa('attacker');
    }
}
