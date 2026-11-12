<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * A compact JWS read strictly before its signature is checked. `jku`, `x5u`,
 * `jwk` and `x5c` are never read; keys come only from the stored JWKS.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CompactToken implements \JsonSerializable
{
    /** @var list<string> Header parameters that refuse the token: unsupported or JWE-only. */
    public const array REFUSED_HEADERS = ['crit', 'b64', 'enc', 'zip'];

    /** @var string What a dump shows for an unknown algorithm. */
    private const string UNKNOWN_ALGORITHM = '[unknown]';

    /** @var \SensitiveParameterValue The token as given. */
    private \SensitiveParameterValue $token;

    /** @var \SensitiveParameterValue The protected header's members. */
    private \SensitiveParameterValue $header;

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

        // Not promoted: held wrapped
        #[\SensitiveParameter]
        string $token,

        // Not promoted: held wrapped
        #[\SensitiveParameter]
        array $header,

        // Not promoted: held wrapped
        #[\SensitiveParameter]
        array $claims,
    ) {
        $this->token  = new \SensitiveParameterValue($token);
        $this->header = new \SensitiveParameterValue($header);
        $this->claims = new \SensitiveParameterValue($claims);
    }

    /**
     * Show a known algorithm and whether a `kid` is present, never a value.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        $algorithm = $this->algorithm();
        $known     = array_key_exists($algorithm, AlgorithmAllowList::ALGORITHMS);

        return ['alg' => $known ? $algorithm : self::UNKNOWN_ALGORITHM, 'kid' => $this->keyId() === null ? null : '[present]', 'token' => '[redacted]'];
    }

    /**
     * Refuse to be serialised; a provider's token lives only for its
     * completion.
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
     * Encode the same redacted view as a dump.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * Parse the token, or return `null` when it is over the cap, not exactly
     * three canonical segments, or has a refused header.
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
        $algorithm = $this->header()['alg'] ?? null;

        return is_string($algorithm) ? $algorithm : '';
    }

    /**
     * The header's `kid`, or `null` when it has none.
     *
     * @return ?string
     */
    public function keyId(): ?string
    {
        $kid = $this->header()['kid'] ?? null;

        return is_string($kid) ? $kid : null;
    }

    /**
     * The protected header's members, for the signature check only.
     *
     * @return array<array-key, mixed>
     */
    public function header(): array
    {
        /** @var array<array-key, mixed> */
        return $this->header->getValue();
    }

    /**
     * The payload's members, with an oversized integer kept as digits so a time
     * claim refuses it.
     *
     * @return array<array-key, mixed>
     */
    public function claims(): array
    {
        /** @var array<array-key, mixed> */
        return $this->claims->getValue();
    }

    /**
     * The payload's members with every number a number, for a validated token.
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
     * The token as given, for the signature check only.
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
     * Whether the header names an algorithm, has no refused parameter, and has
     * a well-typed `kid` and `typ` as written.
     *
     * @param  string  $segment
     * @return bool
     */
    private static function isHeader(#[\SensitiveParameter] string $segment): bool
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
