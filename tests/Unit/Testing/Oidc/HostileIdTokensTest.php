<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Oidc;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\JoseAdapter;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\TimeClaims;
use SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\HostileIdTokens;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Runs each hostile ID token through the JOSE adapter to its named stage.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HostileIdTokens::class)]
#[CoversClass(HostileIdToken::class)]
final class HostileIdTokensTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var int The instant every token is issued and judged at. */
    private const int NOW = 1900000000;

    /** @var int The clock skew the cases are built for and judged with. */
    private const int SKEW = 60;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\HostileIdTokens The cases' keys, generated once. */
    private static ?HostileIdTokens $tokens = null;

    /**
     * Rows of `[name]`: every hostile case.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCases(): iterable
    {
        foreach (array_keys(self::cases()) as $name) {
            yield $name => [$name];
        }
    }

    /**
     * Each hostile token is refused at the stage it names, with the reason it
     * names once its time claims are judged.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideCases')]
    public function testEachHostileTokenIsRefusedAtItsStage(string $name): void
    {
        $case = self::cases()[$name];

        [$stage, $reason] = self::judged($case);

        self::assertSame($case->stage, $stage, $name);
        self::assertSame($stage === 'claims' ? $case->reason : null, $reason, $name);
    }

    /**
     * Every stage is covered: an unread token is `id_token_invalid`, a key or
     * signature refusal `signature_invalid`.
     *
     * @return void
     */
    public function testTheSuiteCoversEveryStage(): void
    {
        $cases  = self::cases();
        $stages = array_count_values(array_map(static fn (HostileIdToken $case): string => $case->stage, $cases));

        ksort($stages);

        self::assertSame(['claims', 'jwks_refused', 'malformed', 'refused', 'unknown', 'unverified'], array_keys($stages));
        self::assertGreaterThanOrEqual(40, count($cases));

        foreach ($cases as $name => $case) {

            $expected = match ($case->stage) {
                'malformed' => FailureReason::ID_TOKEN_INVALID,
                'claims'    => $case->reason,
                default     => FailureReason::SIGNATURE_INVALID,
            };

            self::assertSame($expected, $case->reason, $name);
        }
    }

    /**
     * Rows of `[name, member]`: a key offered in a token's header, by the
     * member it is offered in.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideOfferedKeys(): iterable
    {
        yield from [
            'jwk'                 => ['the attacker\'s key as jwk', 'jwk'],
            'jku'                 => ['the attacker\'s key at a jku', 'jku'],
            'x5u'                 => ['the attacker\'s key at an x5u', 'x5u'],
            'x5c under k1'        => ['the attacker\'s key in x5c', 'x5c'],
            'x5c under a new kid' => ['the attacker\'s key in x5c under an unknown kid', 'x5c'],
        ];
    }

    /**
     * A key offered in a header is the attacker's and signed the token, so a
     * reader that honoured it would verify the token and the case would fail.
     *
     * @param  string  $name
     * @param  string  $member
     * @return void
     */
    #[DataProvider('provideOfferedKeys')]
    public function testAnOfferedKeyWouldVerifyIfHonoured(string $name, string $member): void
    {
        $token = self::cases()[$name]->token;

        self::assertTrue(JwsSigner::verify($token, self::tokens()->attacker->publicKeyPem), $name);
        self::assertArrayHasKey($member, self::headerOf($token), $name);
    }

    /**
     * The certificate in `x5c` is a real one of the attacker's key, and the JWK
     * offered is the attacker's too.
     *
     * @return void
     */
    public function testTheOfferedCertificateAndJwkAreTheAttackers(): void
    {
        $attacker    = self::tokens()->attacker;
        $certificate = self::headerOf(self::cases()['the attacker\'s key in x5c']->token)['x5c'] ?? null;

        self::assertIsArray($certificate);
        self::assertSame([self::tokens()->attackerCertificate], $certificate);

        $pem    = "-----BEGIN CERTIFICATE-----\n" . chunk_split(self::tokens()->attackerCertificate, 64, "\n") . "-----END CERTIFICATE-----\n";
        $public = openssl_pkey_get_public($pem);

        self::assertNotFalse($public);
        self::assertSame($attacker->publicKeyPem, openssl_pkey_get_details($public)['key'] ?? null);
        self::assertSame($attacker->jwk(), self::headerOf(self::cases()['the attacker\'s key as jwk']->token)['jwk'] ?? null);
    }

    /**
     * The token whose header the package and the library read differently is
     * signed correctly by `k1`, so only that disagreement refuses it.
     *
     * @return void
     */
    public function testAHeaderReadTwoWaysIsSignedCorrectly(): void
    {
        self::assertTrue(JwsSigner::verify(self::cases()['a header read two ways']->token, self::tokens()->rsa->publicKeyPem));
    }

    /**
     * The honest token the cases are built from passes every stage, so each
     * refusal is the hostile change's.
     *
     * @return void
     */
    public function testTheHonestTokenIsAccepted(): void
    {
        $tokens = self::tokens();
        $honest = new HostileIdToken(
            JwsSigner::sign(['alg' => 'RS256', 'kid' => 'k2'], self::claims(), $tokens->rsaWithAlgorithm),
            $tokens->jwks(),
            HostileIdTokens::ALGORITHMS,
            'accepted',
            FailureReason::SIGNATURE_INVALID,
        );

        self::assertSame(['accepted', null], self::judged($honest));
    }

    /**
     * The suite is exactly these cases, in this order.
     *
     * @return void
     */
    public function testTheSuiteIsTheseCases(): void
    {
        self::assertSame([
            'alg none, empty signature', 'alg None, empty signature', 'alg none with a signature', 'HS256 with the public key as secret',
            'HS256 with an oct key planted', 'alg the key\'s own alg refuses', 'ES512 with a P-256 key', 'ES256 against an RSA key', 'RS256 against an EC key',
            'kid with a path', 'kid SQL-like', 'kid unknown', 'kid of another case', 'kid "0" against a key with none', 'kid as an array', 'kid as a number',
            'kid too large to be a number', 'kid empty', 'no kid among two RS256 keys',
            'RS256 with a 1024-bit key', 'a JWKS of a 1024-bit key alone', 'a JWKS publishing a private key', 'a JWKS with a key under k1 twice',
            'signed by another key under k1', 'the attacker\'s key as jwk', 'the attacker\'s key at a jku', 'the attacker\'s key at an x5u', 'the attacker\'s key in x5c',
            'the attacker\'s key in x5c under an unknown kid', 'a tampered payload',
            'crit naming an unknown header', 'b64 false', 'a JWE', 'alg repeated in the header', 'a header read two ways', 'sub repeated, escaped',
            'a member repeated in an object', 'a payload that is not an object', 'over the size cap',
            'exp at now less the skew', 'iat past now and the skew', 'nbf past now and the skew', 'exp as a numeric string', 'exp too large to be a number',
            'exp missing', 'iat as a boolean',
        ], array_keys(self::cases()));
    }

    /**
     * Rows of `[name, header]`: the exact header a case's token carries.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>}>
     */
    public static function provideHeaders(): iterable
    {
        yield from [
            'a kid as an array' => ['kid as an array', ['alg' => 'RS256', 'kid' => ['k1']]],
            'a kid as a number' => ['kid as a number', ['alg' => 'RS256', 'kid' => 0]],
            'a crit'            => ['crit naming an unknown header', ['alg' => 'RS256', 'kid' => 'k1', 'crit' => ['x-unknown'], 'x-unknown' => 1]],
            'b64'               => ['b64 false', ['alg' => 'RS256', 'kid' => 'k1', 'b64' => false]],
            'a jku'             => ['the attacker\'s key at a jku', ['alg' => 'RS256', 'kid' => 'attacker', 'jku' => 'https://attacker.example.test/jwks']],
            'an x5u'            => ['the attacker\'s key at an x5u', ['alg' => 'RS256', 'kid' => 'attacker', 'x5u' => 'https://attacker.example.test/cert.pem']],
        ];
    }

    /**
     * A case's token carries exactly its hostile header.
     *
     * @param  string  $name
     * @param  array<string, mixed>  $header
     * @return void
     */
    #[DataProvider('provideHeaders')]
    public function testACasesHeaderIsExact(string $name, array $header): void
    {
        self::assertSame($header, self::headerOf(self::cases()[$name]->token));
    }

    /**
     * Rows of `[name, payload]`: the exact text of a case's payload.
     *
     * @return iterable<string, array{0: string, 1: \Closure(string): string}>
     */
    public static function providePayloads(): iterable
    {
        $json = static fn (array $changes): string => (string) json_encode($changes, JSON_UNESCAPED_SLASHES);
        $base = self::claims();
        $now  = self::NOW;

        yield from [
            'sub repeated'      => ['sub repeated, escaped', static fn (string $open): string => $open . ',"s' . chr(92) . 'u0075b":"someone-else"}'],
            'a member repeated' => ['a member repeated in an object', static fn (string $open): string => $open . ',"address":{"country":"GB","country":"US"}}'],
            'tampered'          => ['a tampered payload', static fn (): string => $json([...$base, 'sub' => 'someone-else'])],
            'exp at the skew'   => ['exp at now less the skew', static fn (): string => $json([...$base, 'exp' => $now - self::SKEW])],
            'iat past the skew' => ['iat past now and the skew', static fn (): string => $json([...$base, 'iat' => $now + self::SKEW + 1])],
            'nbf past the skew' => ['nbf past now and the skew', static fn (): string => $json([...$base, 'nbf' => $now + self::SKEW + 1])],
            'exp as a string'   => ['exp as a numeric string', static fn (): string => $json([...$base, 'exp' => (string) ($now + 300)])],
            'exp too large'     => [
                'exp too large to be a number',
                static fn (string $open): string => str_replace('"exp":' . ($now + 300), '"exp":' . str_repeat('9', 23), $open . '}'),
            ],
            'exp missing'      => ['exp missing', static fn (): string => $json(array_diff_key($base, ['exp' => null]))],
            'iat as a boolean' => ['iat as a boolean', static fn (): string => $json([...$base, 'iat' => true])],
        ];
    }

    /**
     * A case's payload is exactly its hostile text.
     *
     * @param  string  $name
     * @param  \Closure(string): string  $payload
     * @return void
     */
    #[DataProvider('providePayloads')]
    public function testACasesPayloadIsExact(string $name, \Closure $payload): void
    {
        $open = substr((string) json_encode(self::claims(), JSON_UNESCAPED_SLASHES), 0, -1);

        self::assertSame($payload($open), JwsSigner::decode(explode('.', self::cases()[$name]->token)[1]));
    }

    /**
     * A token over the size cap keeps its claims beside its padding.
     *
     * @return void
     */
    public function testATokenOverTheCapKeepsItsClaims(): void
    {
        $payload = (array) json_decode(JwsSigner::decode(explode('.', self::cases()['over the size cap']->token)[1]), true);

        self::assertSame(['iss', 'sub', 'aud', 'iat', 'exp', 'nonce', 'padding'], array_keys($payload));
    }

    /**
     * The skew defaults to a minute, and a token with no `iat` is timed from
     * the epoch.
     *
     * @return void
     */
    public function testTheSkewAndTheFirstInstantDefault(): void
    {
        $cases = self::tokens()->cases(['sub' => 'person']);
        $claim = static fn (string $name, string $member): mixed => ((array) json_decode(JwsSigner::decode(explode('.', $cases[$name]->token)[1]), true))[$member] ?? null;

        self::assertSame(-60, $claim('exp at now less the skew', 'exp'));
        self::assertSame(61, $claim('iat past now and the skew', 'iat'));
    }

    /**
     * Rows of `[name, count of keys]`: a case judged against a JWKS of its own.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideOwnJwks(): iterable
    {
        yield from [
            'the planted key'  => ['HS256 with an oct key planted', ['k1', 'k2', 'e1', 'h1']],
            'with a weak key'  => ['RS256 with a 1024-bit key', ['k1', 'k2', 'e1', 's1']],
            'a weak key alone' => ['a JWKS of a 1024-bit key alone', ['s1']],
            'a private key'    => ['a JWKS publishing a private key', ['k1']],
            'the same key'     => ['a JWKS with a key under k1 twice', ['k1', 'k1']],
            'the honest keys'  => ['kid unknown', ['k1', 'k2', 'e1']],
        ];
    }

    /**
     * A case is judged against exactly the keys it names.
     *
     * @param  string  $name
     * @param  list<string>  $kids
     * @return void
     */
    #[DataProvider('provideOwnJwks')]
    public function testACasesJwksIsExact(string $name, array $kids): void
    {
        self::assertSame($kids, array_map(static fn (array $key): mixed => $key['kid'] ?? null, self::cases()[$name]->jwks['keys']));
    }

    /**
     * What the keys of a hostile JWKS are: a planted one symmetric, a private
     * one with its private members.
     *
     * @return void
     */
    public function testAHostileJwksHoldsWhatItNames(): void
    {
        $cases = self::cases();

        self::assertSame('oct', $cases['HS256 with an oct key planted']->jwks['keys'][3]['kty'] ?? null);
        self::assertArrayHasKey('d', $cases['a JWKS publishing a private key']->jwks['keys'][0]);
        self::assertSame(['RS256', 'PS256', 'ES256'], $cases['alg none, empty signature']->algorithms);
        self::assertSame(['ES256', 'ES512'], $cases['ES512 with a P-256 key']->algorithms);
        self::assertSame(['PS256'], $cases['the attacker\'s key as jwk']->algorithms);
    }

    /**
     * A case not naming its signer is signed with `k1`, and the key a case
     * names signed it.
     *
     * @return void
     */
    public function testACaseIsSignedWithItsKey(): void
    {
        self::assertTrue(JwsSigner::verify(self::cases()['kid unknown']->token, self::tokens()->rsa->publicKeyPem));
        self::assertFalse(JwsSigner::verify(self::cases()['signed by another key under k1']->token, self::tokens()->rsa->publicKeyPem));
    }

    /**
     * How far the adapter lets the case go, and the time claims' reason once it
     * verifies.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken  $case
     * @return array{0: string, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}
     */
    private static function judged(HostileIdToken $case): array
    {
        $allowed = AlgorithmAllowList::of($case->algorithms);
        $token   = CompactToken::parse($case->token, HostileIdTokens::MAX_TOKEN_BYTES);
        $keys    = ProviderKeySet::read((string) json_encode($case->jwks), $allowed, 65536, 50);

        if ($token === null || $keys === null) {
            return [$token === null ? 'malformed' : 'jwks_refused', null];
        }

        $selection = $keys->select($token, $allowed);

        if (!$selection->isFound()) {
            return [$selection->isUnknown() ? 'unknown' : 'refused', null];
        }

        $reason = TimeClaims::check($token->claims(), CarbonImmutable::createFromTimestampUTC(self::NOW), self::SKEW, 300);

        return match (true) {
            !(new JoseAdapter)->verify($token, $selection->key, $allowed) => ['unverified', null],
            $reason !== null                                              => ['claims', $reason],
            default                                                       => ['accepted', null],
        };
    }

    /**
     * The token's header, as plain JSON reads it.
     *
     * @param  string  $token
     * @return array<string, mixed>
     */
    private static function headerOf(string $token): array
    {
        /** @var array<string, mixed> */
        return (array) json_decode(JwsSigner::decode(explode('.', $token)[0]), true);
    }

    /**
     * Every case, built once.
     *
     * @return array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken>
     */
    private static function cases(): array
    {
        return self::tokens()->cases(self::claims(), self::SKEW);
    }

    /**
     * The claims of an otherwise valid token issued now.
     *
     * @return array<string, mixed>
     */
    private static function claims(): array
    {
        return ['iss' => 'https://op.example.test', 'sub' => 'person', 'aud' => 'client', 'iat' => self::NOW, 'exp' => self::NOW + 300, 'nonce' => 'n'];
    }

    /**
     * The cases' keys, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdTokens
     */
    private static function tokens(): HostileIdTokens
    {
        return self::$tokens ??= new HostileIdTokens;
    }
}
