<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * The public keys of an identity provider's JWKS the package admits (SSO-7.3),
 * as read from the provider (`read()`) or from what the connection stores
 * (`fromStored()`), each admitted by `ProviderKey::admit()` for the
 * connection's allow-list.
 *
 * A JWKS is read only when it is a JSON object within the size cap, read as
 * JSON wrote it by `StrictJson` (a repeated member refused, nested ones too, a
 * JSON object never read as a list and a number never as its digits), whose
 * `keys` is a list of at most the cap's number of objects; a key the package
 * does not admit (an `oct` key, a private key, an encryption key, a weak or
 * unknown one) is left out, and the JWKS is refused when two admitted keys
 * share a `kid` or none is admitted. A stored JWKS is admitted again as it is
 * read, so a key whose algorithm has left the allow-list since is never used.
 *
 * `select()` picks the key for a token, never by position and never through the
 * library's key set: the one whose own `kid` is exactly the header's, a string
 * compared byte for byte (an unknown `kid` never falls back to another key); or,
 * for a token with no `kid`, the only key admissible for its algorithm.
 *
 * It holds public keys only.
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
     * The keys a JWKS fetched from the provider gives, or `null` when the JWKS
     * is refused: larger than `maxBytes`, not a JSON object read strictly,
     * without a `keys` list of objects, with more than `maxKeys` keys, with two
     * admitted keys under one `kid`, or with none admitted.
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
     * The keys the connection stores, admitted again for the allow-list; none
     * when it stores none or what it stores cannot be read.
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
     * The key that verifies the token, or why there is none.
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
     * How many of this set's keys the set given lacks, and how many of the
     * given set's keys this set lacks or holds in another form: what a
     * replacement of the given set by this one adds and removes. A key that
     * keeps its `kid` with other members counts as both.
     *
     * @param  self  $before
     * @return array{added: int, removed: int}
     */
    public function changesFrom(self $before): array
    {
        return ['added' => self::missingFrom($this->keys, $before->keys), 'removed' => self::missingFrom($before->keys, $this->keys)];
    }

    /**
     * The key among the candidates: the one candidate when it fits the
     * algorithm; none found when there are none; refused otherwise.
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
     * The keys each entry gives that the package admits, or `null` when an
     * entry is not a JSON object.
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
     * How many of the keys the other keys do not hold in exactly the same form.
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
