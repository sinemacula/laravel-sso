<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * A connection's allow-list of ID token signature algorithms (SSO-7.3): only
 * the asymmetric RSA PKCS #1, RSA-PSS and ECDSA algorithms at 256 bits and
 * above. `none` and every HMAC algorithm can never be on it, whatever a
 * connection's settings say: `of()` refuses them, and nothing in the package
 * can register them with the library.
 *
 * Each algorithm fixes the key it needs: an RSA key for `RS*` and `PS*`, and an
 * elliptic curve key on its own curve for `ES*` (P-256 for ES256, P-384 for
 * ES384, P-521 for ES512), so a key on another curve never verifies it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AlgorithmAllowList
{
    /** @var array<string, ?string> Every algorithm a list may hold, with the curve its key must be on, `null` for an RSA key. */
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
     * The allow-list of the algorithms named, each of which must be one of
     * `ALGORITHMS`, given exactly.
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
     * Whether the algorithm, compared exactly, is on the list.
     *
     * @param  string  $algorithm
     * @return bool
     */
    public function allows(string $algorithm): bool
    {
        return in_array($algorithm, $this->names, true);
    }

    /**
     * The key type an algorithm needs: `RSA` or `EC`; `null` for one the
     * package never verifies.
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
