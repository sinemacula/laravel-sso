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
 * drivers.
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
     * The keys of the use to publish: the current key, then the next one.
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

        usort($keys, static fn (ConnectionKey $one, ConnectionKey $other): int => ($one->state === KeyState::NEXT) <=> ($other->state === KeyState::NEXT));

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
     * Every certificate the connection trusts for the use, oldest first,
     * whatever its dates: expiry is reported, never enforced.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @return list<\SineMacula\Laravel\Sso\Keys\KeySummary>
     *
     * @throws \InvalidArgumentException
     */
    public function trustedCertificates(string $connectionId, KeyUse $use = KeyUse::IDP_SIGNING): array
    {
        if (!$use->isTrustedCertificate()) {
            throw new \InvalidArgumentException(sprintf('[%s] is not a use of a trusted certificate.', $use->value));
        }

        $keys = self::of($connectionId)
            ->where('use', $use->value)
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
     * A query of the connection's keys and certificates on the write
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
     * @return list<bool|int|string|null>
     */
    private static function decryptionRank(ConnectionKey $key): array
    {
        return [$key->state === KeyState::CURRENT, $key->made_current_at?->getTimestamp(), $key->created_at->getTimestamp(), $key->id];
    }
}
