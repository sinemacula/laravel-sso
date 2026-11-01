<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * The read side of a connection's keys and certificates, for the protocol
 * drivers (SSO-2.6, SSO-2.7, SSO-5.9): the key that signs, the keys published,
 * the keys that decrypt, the certificates trusted, and a key's private half.
 *
 * - `current()` and `next()` answer the key of a use in that state, if any.
 * - `published()` answers the current key, then the next one, so metadata and a
 *   JWKS carry both while a rotation is under way (SSO-5.9).
 * - `decryption()` answers the current encryption key, then each retiring one
 *   whose overlap has not ended by the clock's now, newest first, so a response
 *   encrypted for a key just replaced still decrypts (SSO-2.7).
 * - `trustedCertificates()` answers every certificate the connection trusts,
 *   oldest first, whatever its dates: expiry is reported, never enforced
 *   (SSO-2.6).
 * - `privateKey()` decrypts a key's private half for the call that signs or
 *   decrypts with it, as a `Secrets\Secret`; a key of another connection, or a
 *   trusted certificate, is a caller's mistake, a `LogicException`.
 *
 * Every read is on the write connection (SSO-11.3), constrained to the
 * connection's id, and holds nothing between calls (SSO-11.2). A database
 * error, or a ciphertext the encrypter cannot decrypt, propagates.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class KeyRing
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     */
    public function __construct(

        /** The clock the end of an overlap is judged by. */
        private Clock $clock,

        /** The encrypter that decrypts a stored private key. */
        private SecretEncrypter $encrypter,
    ) {}

    /**
     * The connection's current key of the use, if it has one.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return ?\SineMacula\Laravel\Sso\Keys\KeySummary
     *
     * @throws \InvalidArgumentException
     */
    public function current(string $connectionId, KeyUse $use): ?KeySummary
    {
        return $this->inState($connectionId, $use, KeyState::CURRENT);
    }

    /**
     * The connection's next key of the use, if it has one.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return ?\SineMacula\Laravel\Sso\Keys\KeySummary
     *
     * @throws \InvalidArgumentException
     */
    public function next(string $connectionId, KeyUse $use): ?KeySummary
    {
        return $this->inState($connectionId, $use, KeyState::NEXT);
    }

    /**
     * The keys of the use to publish: the current key, then the next one, each
     * when there is one.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return list<\SineMacula\Laravel\Sso\Keys\KeySummary>
     *
     * @throws \InvalidArgumentException
     */
    public function published(string $connectionId, KeyUse $use): array
    {
        $keys = self::of($connectionId)
            ->where('use', $use->value)
            ->whereIn('state', [KeyState::CURRENT->value, KeyState::NEXT->value])
            ->get()
            ->all();

        usort($keys, static fn (ConnectionKey $one, ConnectionKey $other): int => ($one->state === KeyState::CURRENT ? 0 : 1) <=> ($other->state === KeyState::CURRENT ? 0 : 1));

        return array_map(KeySummary::of(...), $keys);
    }

    /**
     * The encryption keys that decrypt: the current one, then each retiring one
     * still within its overlap, the most recently current first.
     *
     * @param  string  $connectionId
     * @return list<\SineMacula\Laravel\Sso\Keys\KeySummary>
     *
     * @throws \InvalidArgumentException
     */
    public function decryption(string $connectionId): array
    {
        $model = new ConnectionKey;
        $now   = UtcDateTime::format($model, $this->clock->now());
        $keys  = self::of($connectionId)
            ->where('use', KeyUse::SP_ENCRYPTION->value)
            ->where(static function (Builder $query) use ($now): void {
                $query->where('state', KeyState::CURRENT->value)
                    ->orWhere(static function (Builder $retiring) use ($now): void {
                        $retiring->where('state', KeyState::RETIRING->value)->where('retiring_until', '>', $now);
                    });
            })
            ->get()
            ->all();

        usort($keys, static fn (ConnectionKey $one, ConnectionKey $other): int => self::decryptionRank($other) <=> self::decryptionRank($one));

        return array_map(KeySummary::of(...), $keys);
    }

    /**
     * Every identity provider certificate the connection trusts, oldest first,
     * whatever its dates.
     *
     * @param  string  $connectionId
     * @return list<\SineMacula\Laravel\Sso\Keys\KeySummary>
     *
     * @throws \InvalidArgumentException
     */
    public function trustedCertificates(string $connectionId): array
    {
        $keys = self::of($connectionId)
            ->where('use', KeyUse::IDP_SIGNING->value)
            ->orderBy('created_at')
            ->orderBy('id')
            ->get()
            ->all();

        return array_values(array_map(KeySummary::of(...), $keys));
    }

    /**
     * The private half of one of the connection's own keys, decrypted, for the
     * call that signs or decrypts with it.
     *
     * @param  string  $connectionId
     * @param  string  $keyId
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     */
    public function privateKey(string $connectionId, string $keyId): Secret
    {
        $key = self::of($connectionId)->whereKey($keyId)->first();

        return new Secret($this->encrypter->decrypt(self::ciphertext($key)));
    }

    /**
     * The stored ciphertext of the key's private half.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @return string
     *
     * @throws \LogicException
     */
    private static function ciphertext(?ConnectionKey $key): string
    {
        if ($key === null || $key->private_key === null) {
            throw new \LogicException('The connection has no private key with that id.');
        }

        return $key->private_key;
    }

    /**
     * The connection's key of the use in the state, if any.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @return ?\SineMacula\Laravel\Sso\Keys\KeySummary
     *
     * @throws \InvalidArgumentException
     */
    private function inState(string $connectionId, KeyUse $use, KeyState $state): ?KeySummary
    {
        $key = self::of($connectionId)
            ->where('use', $use->value)
            ->where('state', $state->value)
            ->orderBy('created_at')
            ->orderBy('id')
            ->first();

        return $key === null ? null : KeySummary::of($key);
    }

    /**
     * A query of the connection's keys and certificates, on the write
     * connection.
     *
     * @param  string  $connectionId
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Sso\Models\ConnectionKey>
     */
    private static function of(string $connectionId): Builder
    {
        return ConnectionKey::query()->useWritePdo()->where('connection_id', $connectionId);
    }

    /**
     * Where the key falls in decryption order, descending: the current key
     * first, then the most recently made current, then the most recently added.
     *
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @return list<int|string|null>
     */
    private static function decryptionRank(ConnectionKey $key): array
    {
        return [$key->state === KeyState::CURRENT ? 1 : 0, $key->made_current_at?->getTimestamp(), $key->created_at->getTimestamp(), $key->id];
    }
}
