<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Tokens;

/**
 * An ID token once every check of SSO-7.3 and SSO-7.4 passed: its signature
 * with a key the connection's JWKS holds, its algorithm, its typed claims, its
 * issuer, audience, authorised party, times, nonce, subject, `auth_time` and
 * `at_hash` (`IdTokenValidator`). Only the validator builds it; the claims
 * assembly reads the identity and authentication claims from it alone, never
 * from UserInfo (SSO-7.5).
 *
 * The issuer is the connection's, exactly. The claims are a provider's values,
 * so they are held in a `\SensitiveParameterValue`: a dump and JSON encoding
 * show the issuer and the names of the claims, never the subject or a value,
 * and it refuses to be serialised or unserialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ValidatedIdToken implements \JsonSerializable
{
    /** @var \SensitiveParameterValue The token's claims, as validated. */
    private \SensitiveParameterValue $claims;

    /**
     * Constructor.
     *
     * @param  string  $issuer
     * @param  string  $subject
     * @param  array<array-key, mixed>  $claims
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The token's `iss`, which is the connection's issuer. */
        public string $issuer,

        // The token's `sub`, a non-empty string; held with the claims
        string $subject,

        // The token's claims, as validated; held wrapped
        #[\SensitiveParameter]
        array $claims,
    ) {
        if ($subject === '' || ($claims['sub'] ?? null) !== $subject || ($claims['iss'] ?? null) !== $issuer) {
            throw new \InvalidArgumentException('A validated ID token carries its own issuer and a non-empty subject.');
        }

        $this->claims = new \SensitiveParameterValue($claims);
    }

    /**
     * What a dump shows: the issuer and the names of the claims, never a value.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['issuer' => $this->issuer, 'claims' => array_keys($this->claims())];
    }

    /**
     * Refuse to be serialised: the token lives only for its completion.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A validated ID token cannot be serialised.');
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
        throw new \LogicException('A validated ID token cannot be unserialised.');
    }

    /**
     * What JSON encoding shows: the same as a dump, never a value.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * The token's `sub`, exactly as received.
     *
     * @return string
     */
    public function subject(): string
    {
        $subject = $this->claims()['sub'] ?? null;

        return is_string($subject) ? $subject : '';
    }

    /**
     * The token's claims, as validated.
     *
     * @return array<array-key, mixed>
     */
    public function claims(): array
    {
        /** @var array<array-key, mixed> */
        return $this->claims->getValue();
    }

    /**
     * One claim, or `null` when the token has none of the name.
     *
     * @param  string  $name
     * @return mixed
     */
    public function claim(string $name): mixed
    {
        return $this->claims()[$name] ?? null;
    }
}
