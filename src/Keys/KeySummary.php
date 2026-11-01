<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;

/**
 * What a helper returns for one of a connection's keys or trusted certificates
 * (SSO-2.5, SSO-2.6, SSO-2.7): its id, connection, use and state, its type and
 * size, its public half masked as `Secrets\MaskedKey` (the certificate, the
 * public key and the fingerprint), the certificate's validity, when it was made
 * current, and until when a retiring key is still accepted. It never holds a
 * private key.
 *
 * A certificate's dates are reported, never enforced: trust comes from the
 * configured certificate (SSO-2.6). `isExpiredAt()` and `expiresWithin()`
 * answer the report.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class KeySummary implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @param  int  $bits
     * @param  \SineMacula\Laravel\Sso\Secrets\MaskedKey  $key
     * @param  ?\Carbon\CarbonImmutable  $notBefore
     * @param  ?\Carbon\CarbonImmutable  $notAfter
     * @param  ?\Carbon\CarbonImmutable  $madeCurrentAt
     * @param  ?\Carbon\CarbonImmutable  $retiringUntil
     * @param  \Carbon\CarbonImmutable  $createdAt
     */
    public function __construct(

        /** The row's id. */
        public string $id,

        /** The connection it belongs to. */
        public string $connectionId,

        /** What it is for. */
        public KeyUse $use,

        /** Where a key of the service provider's own is in its rotation; `null` for a trusted certificate. */
        public ?KeyState $state,

        /** The kind of key. */
        public KeyType $type,

        /** The RSA modulus or the elliptic curve's size, in bits. */
        public int $bits,

        /** The public half: the certificate, the public key and the fingerprint. */
        public MaskedKey $key,

        /** When the certificate's validity starts, when there is a certificate. */
        public ?CarbonImmutable $notBefore,

        /** When the certificate's validity ends, when there is a certificate. */
        public ?CarbonImmutable $notAfter,

        /** When the key was made current, once it has been. */
        public ?CarbonImmutable $madeCurrentAt,

        /** Until when a retiring key is still accepted for decryption. */
        public ?CarbonImmutable $retiringUntil,

        /** When the row was added. */
        public CarbonImmutable $createdAt,
    ) {}

    /**
     * The summary of the row: its public half read from its certificate, or
     * from its public key when it has none.
     *
     * @param  \SineMacula\Laravel\Sso\Models\ConnectionKey  $key
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(ConnectionKey $key): self
    {
        $masked = $key->certificate !== null ? MaskedKey::fromCertificate($key->certificate) : MaskedKey::fromPublicKey($key->public_key);

        return new self(
            id: $key->id,
            connectionId: $key->connection_id,
            use: $key->use,
            state: $key->state,
            type: $key->key_type,
            bits: $key->key_bits,
            key: $masked,
            notBefore: $key->not_before,
            notAfter: $key->not_after,
            madeCurrentAt: $key->made_current_at,
            retiringUntil: $key->retiring_until,
            createdAt: $key->created_at,
        );
    }

    /**
     * Whether the certificate's validity has ended by the instant given. A key
     * with no certificate never expires.
     *
     * @param  \Carbon\CarbonInterface  $now
     * @return bool
     */
    public function isExpiredAt(CarbonInterface $now): bool
    {
        return $this->notAfter !== null && $this->notAfter->lessThanOrEqualTo($now);
    }

    /**
     * Whether the certificate's validity ends within the seconds given of the
     * instant given, or has already ended.
     *
     * @param  \Carbon\CarbonInterface  $now
     * @param  int  $seconds
     * @return bool
     */
    public function expiresWithin(CarbonInterface $now, int $seconds): bool
    {
        return $this->notAfter !== null && $this->notAfter->lessThanOrEqualTo($now->toImmutable()->addSeconds($seconds));
    }

    /**
     * The summary, with snake_case keys and each time as an ISO 8601 UTC
     * string.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'id'              => $this->id,
            'connection_id'   => $this->connectionId,
            'use'             => $this->use->value,
            'state'           => $this->state?->value,
            'type'            => $this->type->value,
            'bits'            => $this->bits,
            'key'             => $this->key->jsonSerialize(),
            'not_before'      => self::time($this->notBefore),
            'not_after'       => self::time($this->notAfter),
            'made_current_at' => self::time($this->madeCurrentAt),
            'retiring_until'  => self::time($this->retiringUntil),
            'created_at'      => self::time($this->createdAt),
        ];
    }

    /**
     * The instant as an ISO 8601 UTC string, or `null`.
     *
     * @param  ?\Carbon\CarbonImmutable  $time
     * @return ?string
     */
    private static function time(?CarbonImmutable $time): ?string
    {
        return $time?->utc()->format('Y-m-d\TH:i:s\Z');
    }
}
