<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * A JWS in compact serialisation as the package reads it (RFC 7515 §7.1,
 * SSO-7.3), before its signature is checked: an ID token, or anything else that
 * claims to be one.
 *
 * `parse()` answers `null` for anything the package never verifies:
 *
 * - more bytes than the cap given, or none;
 * - anything but exactly three segments, so a JWE (five) or a JSON
 *   serialisation is never read;
 * - a segment that is not canonical unpadded base64url, an empty header or
 *   payload, or an empty signature;
 * - a header or payload that is not one JSON object read by `StrictJson`
 *   (duplicate members refused, nested ones too);
 * - a header without `alg` as a non-empty string, or with `crit` or `b64`
 *   (whose meaning the package would have to apply), or with `enc` or `zip`
 *   (which only a JWE carries);
 * - a header `kid` that is present but not a non-empty string, or a `typ` that
 *   is present but not a string, a number too large for an integer being
 *   neither (`StrictJson::decodeMembers()`).
 *
 * `jku`, `x5u`, `jwk` and `x5c` are never read: a key comes only from the JWKS
 * stored with the connection.
 *
 * The token, its claims and its signature are a provider's token (SSO-7.6), so
 * they are held in `\SensitiveParameterValue`: a dump shows the algorithm and
 * whether a `kid` is present, never a value, and it refuses to be serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CompactToken
{
    /** @var list<string> Header parameters whose presence refuses the token. */
    public const array REFUSED_HEADERS = ['crit', 'b64', 'enc', 'zip'];

    /** @var \SensitiveParameterValue The token as given. */
    private \SensitiveParameterValue $token;

    /** @var \SensitiveParameterValue The payload's members. */
    private \SensitiveParameterValue $claims;

    /**
     * Constructor.
     *
     * @param  string  $token
     * @param  array<array-key, mixed>  $header
     * @param  array<array-key, mixed>  $claims
     */
    private function __construct(

        // The token as given; held wrapped
        #[\SensitiveParameter]
        string $token,

        /** The protected header's members. */
        public array $header,

        // The payload's members; held wrapped
        #[\SensitiveParameter]
        array $claims,
    ) {
        $this->token  = new \SensitiveParameterValue($token);
        $this->claims = new \SensitiveParameterValue($claims);
    }

    /**
     * What a dump shows: the algorithm and whether the header names a key,
     * never the token or a claim.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['alg' => $this->algorithm(), 'kid' => $this->keyId() === null ? null : '[present]', 'token' => '[redacted]'];
    }

    /**
     * Refuse to be serialised: a provider's token is used only during the
     * completion that received it (SSO-7.6).
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A provider token cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A provider token cannot be unserialised.');
    }

    /**
     * The token the text holds, or `null` when it is not a compact JWS the
     * package reads, within the cap given in bytes.
     *
     * @param  string  $token
     * @param  int  $maxBytes
     * @return ?self
     */
    public static function parse(#[\SensitiveParameter] string $token, int $maxBytes): ?self
    {
        $length   = strlen($token);
        $segments = explode('.', $token);

        if ($length === 0 || $length > $maxBytes || count($segments) !== 3) {
            return null;
        }

        $header = self::object($segments[0]);
        $claims = self::object($segments[1]);

        if ($header === null || $claims === null || !self::isSignature($segments[2]) || !self::isHeader($segments[0])) {
            return null;
        }

        return new self($token, $header, $claims);
    }

    /**
     * The header's `alg`.
     *
     * @return string
     */
    public function algorithm(): string
    {
        $algorithm = $this->header['alg'] ?? null;

        return is_string($algorithm) ? $algorithm : '';
    }

    /**
     * The header's `kid`, or `null` when it has none.
     *
     * @return ?string
     */
    public function keyId(): ?string
    {
        $kid = $this->header['kid'] ?? null;

        return is_string($kid) ? $kid : null;
    }

    /**
     * The payload's members as `StrictJson::decodeObject()` reads them, so a
     * time claim too large for an integer is its digits and is refused.
     *
     * @return array<array-key, mixed>
     */
    public function claims(): array
    {
        /** @var array<array-key, mixed> */
        return $this->claims->getValue();
    }

    /**
     * The payload's members with every number a number, never its digits: what
     * a token that passed its checks hands on.
     *
     * @return array<array-key, mixed>
     */
    public function members(): array
    {
        return StrictJson::decodeMembers($this->payload()) ?? [];
    }

    /**
     * The payload's JSON text.
     *
     * @return string
     */
    public function payload(): string
    {
        return (string) Base64Url::decode(explode('.', $this->compact())[1] ?? '');
    }

    /**
     * The token as given, for the signature check and nothing else.
     *
     * @return string
     */
    public function compact(): string
    {
        /** @var string */
        return $this->token->getValue();
    }

    /**
     * The object a header or payload segment holds, or `null`.
     *
     * @param  string  $segment
     * @return ?array<array-key, mixed>
     */
    private static function object(#[\SensitiveParameter] string $segment): ?array
    {
        $json = Base64Url::decode($segment);

        return $json === null || $json === '' ? null : StrictJson::decodeObject($json);
    }

    /**
     * Whether the segment is a non-empty signature.
     *
     * @param  string  $segment
     * @return bool
     */
    private static function isSignature(#[\SensitiveParameter] string $segment): bool
    {
        $signature = Base64Url::decode($segment);

        return $signature !== null && $signature !== '';
    }

    /**
     * Whether the header segment names an algorithm, carries nothing that
     * refuses it, and has a well-typed `kid` and `typ` when it has them, as
     * JSON wrote them.
     *
     * @param  string  $segment
     * @return bool
     */
    private static function isHeader(string $segment): bool
    {
        $header  = StrictJson::decodeMembers((string) Base64Url::decode($segment)) ?? [];
        $alg     = $header['alg']                                                  ?? null;
        $kid     = array_key_exists('kid', $header) ? $header['kid'] : '-';
        $typ     = array_key_exists('typ', $header) ? $header['typ'] : '';
        $refused = array_intersect(self::REFUSED_HEADERS, array_keys($header));
        $named   = is_string($alg) && $alg !== '';
        $keyed   = is_string($kid) && $kid !== '';

        return $named && $keyed && is_string($typ) && $refused === [];
    }
}
