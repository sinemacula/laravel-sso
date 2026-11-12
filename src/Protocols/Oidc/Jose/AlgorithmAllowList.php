<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * A connection's ID token signature algorithm allow-list: asymmetric RS, PS and
 * ES only, so `none` and HMAC can never be allowed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AlgorithmAllowList
{
    /** @var array<string, ?string> Each permitted algorithm and its key's curve, `null` for RSA. */
    public const array ALGORITHMS = [
        'RS256' => null,
        'RS384' => null,
        'RS512' => null,
        'PS256' => null,
        'PS384' => null,
        'PS512' => null,
        'ES256' => 'P-256',
        'ES384' => 'P-384',
        'ES512' => 'P-521',
    ];

    /**
     * Constructor.
     *
     * @param  list<string>  $names
     */
    private function __construct(

        /** The algorithms allowed, each once, in the order given. */
        public array $names,
    ) {}

    /**
     * Build the list, refusing any name not exactly in `ALGORITHMS`.
     *
     * @param  array<array-key, mixed>  $names
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(array $names): self
    {
        $allowed = [];

        foreach ($names as $name) {

            if (!is_string($name) || !array_key_exists($name, self::ALGORITHMS)) {
                throw new \InvalidArgumentException('An ID token algorithm allow-list holds only RS, PS and ES algorithms of 256 bits and above.');
            }

            $allowed[$name] = $name;
        }

        if ($allowed === []) {
            throw new \InvalidArgumentException('An ID token algorithm allow-list holds at least one algorithm.');
        }

        return new self(array_values($allowed));
    }

    /**
     * Whether the algorithm is on the list, compared exactly.
     *
     * @param  string  $algorithm
     * @return bool
     */
    public function allows(string $algorithm): bool
    {
        return in_array($algorithm, $this->names, true);
    }

    /**
     * The key type an algorithm needs, `RSA` or `EC`, or `null` for one never
     * verified.
     *
     * @param  string  $algorithm
     * @return ?string
     */
    public static function keyTypeOf(string $algorithm): ?string
    {
        if (!array_key_exists($algorithm, self::ALGORITHMS)) {
            return null;
        }

        return self::ALGORITHMS[$algorithm] === null ? 'RSA' : 'EC';
    }

    /**
     * The curve an `ES*` algorithm's key must be on; `null` for any other.
     *
     * @param  string  $algorithm
     * @return ?string
     */
    public static function curveOf(string $algorithm): ?string
    {
        return self::ALGORITHMS[$algorithm] ?? null;
    }
}
