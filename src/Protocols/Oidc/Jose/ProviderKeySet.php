<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * The admitted public keys of a provider's JWKS. Stored keys are admitted again
 * on read, so a key whose algorithm left the allow-list is never used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProviderKeySet
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey>  $keys
     */
    private function __construct(

        /** The keys admitted, in the order the JWKS gave them. */
        public array $keys,
    ) {}

    /**
     * Read a fetched JWKS, or `null` when it is oversized, malformed, has too
     * many keys, repeats a `kid` or admits none.
     *
     * @param  string  $json
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @param  int  $maxBytes
     * @param  int  $maxKeys
     * @return ?self
     */
    public static function read(string $json, AlgorithmAllowList $allowed, int $maxBytes, int $maxKeys): ?self
    {
        $document = strlen($json) > $maxBytes ? null : StrictJson::decodeAsWritten($json);
        $entries  = $document->keys ?? null;

        if (!is_array($entries) || count($entries) > $maxKeys) {
            return null;
        }

        $keys = self::admitted($entries, $allowed);

        return $keys === null || $keys === [] || self::repeatsKeyId($keys) ? null : new self($keys);
    }

    /**
     * Read the stored keys, admitting each again; empty when unreadable.
     *
     * @param  ?string  $stored
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return self
     */
    public static function fromStored(?string $stored, AlgorithmAllowList $allowed): self
    {
        $entries = $stored === null ? null : json_decode($stored);

        return new self(is_array($entries) ? self::admitted($entries, $allowed) ?? [] : []);
    }

    /**
     * The stored form: a JSON list of each key's public members.
     *
     * @return string
     */
    public function toStored(): string
    {
        return (string) json_encode(array_map(static fn (ProviderKey $key): array => $key->toArray(), $this->keys), JSON_UNESCAPED_SLASHES);
    }

    /**
     * The key for the token: by exact `kid`, or with no `kid` the only key that
     * fits the algorithm. An unknown `kid` never falls back.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken  $token
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection
     */
    public function select(CompactToken $token, AlgorithmAllowList $allowed): KeySelection
    {
        $algorithm = $token->algorithm();
        $kid       = $token->keyId();

        if (!$allowed->allows($algorithm)) {
            return KeySelection::refused();
        }

        $candidates = $kid === null
            ? array_filter($this->keys, static fn (ProviderKey $key): bool => $key->fits($algorithm, $allowed))
            : array_filter($this->keys, static fn (ProviderKey $key): bool => $key->keyId() === $kid);

        return self::selected(array_values($candidates), $algorithm, $allowed);
    }

    /**
     * Count the keys added and removed since the given set; a key whose members
     * changed counts as both.
     *
     * @param  self  $before
     * @return array{added: int, removed: int}
     */
    public function changesFrom(self $before): array
    {
        return ['added' => self::missingFrom($this->keys, $before->keys), 'removed' => self::missingFrom($before->keys, $this->keys)];
    }

    /**
     * Select the sole candidate if it fits; refuse an ambiguous or unfit one.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey>  $candidates
     * @param  string  $algorithm
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection
     */
    private static function selected(array $candidates, string $algorithm, AlgorithmAllowList $allowed): KeySelection
    {
        return match (true) {
            $candidates        === []                                              => KeySelection::unknown(),
            count($candidates) === 1 && $candidates[0]->fits($algorithm, $allowed) => KeySelection::found($candidates[0]),
            default                                                                => KeySelection::refused(),
        };
    }

    /**
     * The admitted keys, or `null` when an entry is not a JSON object.
     *
     * @param  array<array-key, mixed>  $entries
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return ?list<\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey>
     */
    private static function admitted(array $entries, AlgorithmAllowList $allowed): ?array
    {
        $keys = [];

        foreach ($entries as $entry) {

            if (!$entry instanceof \stdClass) {
                return null;
            }

            $keys[] = ProviderKey::admit((array) $entry, $allowed);
        }

        return array_values(array_filter($keys, static fn (?ProviderKey $key): bool => $key !== null));
    }

    /**
     * Whether two of the keys share a `kid`.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey>  $keys
     * @return bool
     */
    private static function repeatsKeyId(array $keys): bool
    {
        $kids = array_filter(array_map(static fn (ProviderKey $key): ?string => $key->keyId(), $keys), is_string(...));

        return count($kids) !== count(array_unique($kids));
    }

    /**
     * How many of the keys are not among the others in exactly the same form.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey>  $keys
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey>  $others
     * @return int
     */
    private static function missingFrom(array $keys, array $others): int
    {
        $held = array_map(static fn (ProviderKey $key): array => $key->toArray(), $others);

        return count(array_filter($keys, static fn (ProviderKey $key): bool => !in_array($key->toArray(), $held, true)));
    }
}
