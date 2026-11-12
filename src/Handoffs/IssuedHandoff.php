<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use Carbon\CarbonImmutable;

/**
 * A handoff code as issued, with its stored expiry and opaque reference.
 *
 * An issuer that holds a reservation must answer a reference.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IssuedHandoff
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffCode  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  ?string  $reference
     */
    public function __construct(

        /** The code, revealed only on the redirect. */
        public HandoffCode $code,

        /** When the code expires. */
        public CarbonImmutable $expiresAt,

        /** The code's opaque reference, never the code. */
        public ?string $reference = null,
    ) {}

    /**
     * Dump the expiry, never the code.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['code' => '[redacted]', 'expires_at' => $this->expiresAt->toIso8601ZuluString()];
    }

    /**
     * Refuse to be serialised: it holds the code.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('An issued handoff cannot be serialised.');
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
        throw new \LogicException('An issued handoff cannot be unserialised.');
    }
}
