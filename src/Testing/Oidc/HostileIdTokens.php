<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * The hand-built hostile ID token suite from `docs/design/jose-library.md`. Key
 * generation takes tens of milliseconds, so a test class may share one set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class HostileIdTokens
{
    /** @var list<string> The allow-list most cases are judged under. */
    public const array ALGORITHMS = ['RS256', 'PS256', 'ES256'];

    /** @var int The size cap the oversized case passes, in bytes. */
    public const int MAX_TOKEN_BYTES = 16384;

    /** @var string The stage where the token is not read. */
    private const string MALFORMED = 'malformed';

    /** @var string The stage where key selection refuses it. */
    private const string REFUSED = 'refused';

    /** @var string The stage where no stored key matches, even after a refetch. */
    private const string UNKNOWN = 'unknown';

    /** @var string The stage where the signature does not verify. */
    private const string UNVERIFIED = 'unverified';

    /** @var \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey `k1`: RSA, published with no `alg`. */
    public FakeSigningKey $rsa;

    /** @var \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey `k2`: RSA, published with `alg` RS256. */
    public FakeSigningKey $rsaWithAlgorithm;

    /** @var \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey `e1`: P-256, published with `alg` ES256. */
    public FakeSigningKey $ec;

    /** @var \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey An attacker's RSA key, never published. */
    public FakeSigningKey $attacker;

    /** @var \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey `s1`: a 1024-bit RSA key. */
    public FakeSigningKey $weak;

    /** @var string A self-signed certificate of the attacker's key, as base64 DER. */
    public string $attackerCertificate;

    /**
     * Constructor.
     *
     * @throws \LogicException
     */
    public function __construct()
    {
        $this->rsa              = FakeSigningKey::rsa('k1');
        $this->rsaWithAlgorithm = FakeSigningKey::rsa('k2');
        $this->ec               = FakeSigningKey::ec('e1');
        $this->attacker         = FakeSigningKey::rsa('attacker');
        $this->weak             = FakeSigningKey::rsa('s1', 1024);

        $this->attackerCertificate = $this->attacker->certificate();
    }

    /**
     * The honest JWKS of `k1`, `k2` and `e1`.
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    public function jwks(): array
    {
        return ['keys' => [$this->rsa->jwk(), $this->rsaWithAlgorithm->jwk('RS256'), $this->ec->jwk('ES256')]];
    }

    /**
     * Every hostile case by name, built from the claims of an otherwise valid
     * token whose `iat` is now.
     *
     * @param  array<string, mixed>  $claims
     * @param  int  $skewSeconds
     * @return array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken>
     */
    public function cases(array $claims, int $skewSeconds = 60): array
    {
        return [
            ...$this->algorithmCases($claims),
            ...$this->keyIdCases($claims),
            ...$this->keyCases($claims),
            ...$this->headerCases($claims),
            ...$this->claimCases($claims, $skewSeconds),
        ];
    }

    /**
     * `none`, HMAC confusion and keys of the wrong type or curve.
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken>
     */
    private function algorithmCases(array $claims): array
    {
        $planted = ['keys' => [...$this->jwks()['keys'], ['kty' => 'oct', 'kid' => 'h1', 'alg' => 'HS256', 'k' => JwsSigner::encode('planted-secret-of-32-bytes-long!')]]];
        $e0      = ['keys' => [$this->ec->withKid('e0')->jwk()]];

        return [
            'alg none, empty signature'           => $this->case($this->token($claims, 'none', 'k1')->unsigned(), self::MALFORMED),
            'alg None, empty signature'           => $this->case($this->token($claims, 'None', 'k1')->unsigned(), self::MALFORMED),
            'alg none with a signature'           => $this->case($this->token($claims, 'none', 'k1')->hmac('x'), self::REFUSED),
            'HS256 with the public key as secret' => $this->case($this->token($claims, 'HS256', 'k1')->hmac($this->rsa->publicKeyPem), self::REFUSED),
            'HS256 with an oct key planted'       => $this->case($this->token($claims, 'HS256', 'h1')->hmac('planted-secret-of-32-bytes-long!'), self::REFUSED, $planted),
            'alg the key\'s own alg refuses'      => $this->case($this->token($claims, 'PS256', 'k2', $this->rsaWithAlgorithm), self::REFUSED),
            'ES512 with a P-256 key'              => $this->case($this->token($claims, 'ES512', 'e0', $this->ec), self::REFUSED, $e0, ['ES256', 'ES512']),
            'ES256 against an RSA key'            => $this->case($this->token($claims, 'ES256', 'k1', $this->ec), self::REFUSED),
            'RS256 against an EC key'             => $this->case($this->token($claims, 'RS256', 'e1'), self::REFUSED),
        ];
    }

    /**
     * `kid` injection and a token with no `kid` among several keys.
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken>
     */
    private function keyIdCases(array $claims): array
    {
        $keyless = ['keys' => [$this->rsa->withKid(null)->jwk()]];

        return [
            'kid with a path'                 => $this->case($this->token($claims, 'RS256', '../../../../etc/passwd'), self::UNKNOWN),
            'kid SQL-like'                    => $this->case($this->token($claims, 'RS256', 'k1\' OR \'1\'=\'1'), self::UNKNOWN),
            'kid unknown'                     => $this->case($this->token($claims, 'RS256', 'unknown'), self::UNKNOWN),
            'kid of another case'             => $this->case($this->token($claims, 'RS256', 'K1'), self::UNKNOWN),
            'kid "0" against a key with none' => $this->case($this->token($claims, 'RS256', '0'), self::UNKNOWN, $keyless),
            'kid as an array'                 => $this->case($this->token($claims, 'RS256', null)->withHeader('kid', ['k1']), self::MALFORMED),
            'kid as a number'                 => $this->case($this->token($claims, 'RS256', null)->withHeader('kid', 0), self::MALFORMED),
            'kid too large to be a number'    => $this->case($this->token($claims, 'RS256', null)->withHeaderJson('{"alg":"RS256","kid":99999999999999999999}'), self::MALFORMED),
            'kid empty'                       => $this->case($this->token($claims, 'RS256', null)->withHeader('kid', ''), self::MALFORMED),
            'no kid among two RS256 keys'     => $this->case($this->token($claims, 'RS256', null), self::REFUSED),
        ];
    }

    /**
     * Keys the JWKS must never let verify: weak, private, another's, offered in
     * the header.
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken>
     */
    private function keyCases(array $claims): array
    {
        $withWeak    = ['keys' => [...$this->jwks()['keys'], $this->weak->jwk()]];
        $onlyWeak    = ['keys' => [$this->weak->jwk()]];
        $onlyPrivate = ['keys' => [$this->rsa->privateJwk()]];
        $twice       = ['keys' => [$this->rsa->jwk(), $this->rsa->jwk()]];
        $tampered    = $this->token([...$claims, 'sub' => 'someone-else'], 'RS256', 'k1')->withSignatureOf((string) $this->token($claims, 'RS256', 'k1'));

        return [
            'RS256 with a 1024-bit key'        => $this->case($this->token($claims, 'RS256', 's1', $this->weak), self::UNKNOWN, $withWeak),
            'a JWKS of a 1024-bit key alone'   => $this->case($this->token($claims, 'RS256', 's1', $this->weak), 'jwks_refused', $onlyWeak),
            'a JWKS publishing a private key'  => $this->case($this->token($claims, 'RS256', 'k1'), 'jwks_refused', $onlyPrivate),
            'a JWKS with a key under k1 twice' => $this->case($this->token($claims, 'RS256', 'k1'), 'jwks_refused', $twice),
            'signed by another key under k1'   => $this->case($this->token($claims, 'RS256', 'k1', $this->attacker), self::UNVERIFIED),
            ...$this->offeredKeyCases($claims),
            'a tampered payload' => $this->case($tampered, self::UNVERIFIED),
        ];
    }

    /**
     * The attacker's own signing key offered in the header, so a reader that
     * honoured it would verify the token.
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken>
     */
    private function offeredKeyCases(array $claims): array
    {
        $x5c      = [$this->attackerCertificate];
        $known    = $this->token($claims, 'RS256', 'k1', $this->attacker);
        $unknown  = $this->token($claims, 'RS256', 'attacker', $this->attacker);
        $keyless  = $this->token($claims, 'PS256', null, $this->attacker);
        $document = 'https://attacker.example.test/';

        return [
            'the attacker\'s key as jwk'                      => $this->case($keyless->withHeader('jwk', $this->attacker->jwk()), self::UNVERIFIED, null, ['PS256']),
            'the attacker\'s key at a jku'                    => $this->case($unknown->withHeader('jku', $document . 'jwks'), self::UNKNOWN),
            'the attacker\'s key at an x5u'                   => $this->case($unknown->withHeader('x5u', $document . 'cert.pem'), self::UNKNOWN),
            'the attacker\'s key in x5c'                      => $this->case($known->withHeader('x5c', $x5c), self::UNVERIFIED),
            'the attacker\'s key in x5c under an unknown kid' => $this->case($unknown->withHeader('x5c', $x5c), self::UNKNOWN),
        ];
    }

    /**
     * Headers and serialisations the package never reads.
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken>
     */
    private function headerCases(array $claims): array
    {
        $payload = json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $open    = substr($payload, 0, -1);
        $k1      = $this->token($claims, 'RS256', 'k1');

        return [
            'crit naming an unknown header'   => $this->case($this->token($claims, 'RS256', 'k1')->withHeader('crit', ['x-unknown'])->withHeader('x-unknown', 1), self::MALFORMED),
            'b64 false'                       => $this->case($this->token($claims, 'RS256', 'k1')->withHeader('b64', false), self::MALFORMED),
            'a JWE'                           => $this->case($this->token($claims, 'RSA-OAEP', 'k1')->withHeader('enc', 'A256GCM')->asJwe(), self::MALFORMED),
            'alg repeated in the header'      => $this->case($this->token($claims, 'RS256', 'k1')->withHeaderJson('{"alg":"RS256","kid":"k1","alg":"none"}'), self::MALFORMED),
            'a header read two ways'          => $this->case($k1->withHeaderJson('{"alg":"RS256","kid":"k1","x":99999999999999999999}'), self::UNVERIFIED),
            'sub repeated, escaped'           => $this->case($this->token($claims, 'RS256', 'k1')->withPayloadJson($open . ',"s\u0075b":"someone-else"}'), self::MALFORMED),
            'a member repeated in an object'  => $this->case($k1->withPayloadJson($open . ',"address":{"country":"GB","country":"US"}}'), self::MALFORMED),
            'a payload that is not an object' => $this->case($this->token($claims, 'RS256', 'k1')->withPayloadJson('["sub"]'), self::MALFORMED),
            'over the size cap'               => $this->case($this->token([...$claims, 'padding' => str_repeat('a', self::MAX_TOKEN_BYTES)], 'RS256', 'k1'), self::MALFORMED),
        ];
    }

    /**
     * The time claims at and past their boundaries, and of the wrong type.
     *
     * @param  array<string, mixed>  $claims
     * @param  int  $skewSeconds
     * @return array<string, \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken>
     */
    private function claimCases(array $claims, int $skewSeconds): array
    {
        $issued = is_int($claims['iat'] ?? null) ? $claims['iat'] : 0;

        return [
            'exp at now less the skew'     => $this->claims([...$claims, 'exp' => $issued - $skewSeconds], FailureReason::ASSERTION_EXPIRED),
            'iat past now and the skew'    => $this->claims([...$claims, 'iat' => $issued + $skewSeconds + 1], FailureReason::ASSERTION_EXPIRED),
            'nbf past now and the skew'    => $this->claims([...$claims, 'nbf' => $issued + $skewSeconds + 1], FailureReason::ASSERTION_EXPIRED),
            'exp as a numeric string'      => $this->claims([...$claims, 'exp' => (string) ($issued + 300)], FailureReason::ID_TOKEN_INVALID),
            'exp too large to be a number' => $this->claims([...$claims, 'exp' => '99999999999999999999999'], FailureReason::ID_TOKEN_INVALID),
            'exp missing'                  => $this->claims(array_diff_key($claims, ['exp' => null]), FailureReason::ID_TOKEN_INVALID),
            'iat as a boolean'             => $this->claims([...$claims, 'iat' => true], FailureReason::ID_TOKEN_INVALID),
        ];
    }

    /**
     * A case refused once its signature verifies, by its claims; an `exp` too
     * large to be a number is written bare.
     *
     * @param  array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken
     */
    private function claims(array $claims, FailureReason $reason): HostileIdToken
    {
        $json  = json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $token = $this->token($claims, 'RS256', 'k1')->withPayloadJson(str_replace('"99999999999999999999999"', '99999999999999999999999', $json));

        return new HostileIdToken((string) $token, $this->jwks(), self::ALGORITHMS, 'claims', $reason);
    }

    /**
     * A case refused at the stage, with the honest JWKS and allow-list unless
     * given.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $token
     * @param  string  $stage
     * @param  ?array{keys: list<array<string, mixed>>}  $jwks
     * @param  ?list<string>  $algorithms
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\HostileIdToken
     */
    private function case(FakeIdToken $token, string $stage, ?array $jwks = null, ?array $algorithms = null): HostileIdToken
    {
        $reason = $stage === self::MALFORMED ? FailureReason::ID_TOKEN_INVALID : FailureReason::SIGNATURE_INVALID;

        return new HostileIdToken((string) $token, $jwks ?? $this->jwks(), $algorithms ?? self::ALGORITHMS, $stage, $reason);
    }

    /**
     * A token signed with the key, or `k1`; a `null` `kid` is left out.
     *
     * @param  array<string, mixed>  $claims
     * @param  string  $algorithm
     * @param  ?string  $kid
     * @param  ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken
     */
    private function token(array $claims, string $algorithm, ?string $kid, ?FakeSigningKey $key = null): FakeIdToken
    {
        $header = array_filter(['alg' => $algorithm, 'kid' => $kid], static fn (?string $value): bool => $value !== null);

        return new FakeIdToken($key ?? $this->rsa, $header, $claims);
    }
}
