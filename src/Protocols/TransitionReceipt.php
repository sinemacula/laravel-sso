<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

/**
 * Lets one sign-in finish across the key removal its own token's JWKS refetch
 * made. It names that exact transition and is never stored.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TransitionReceipt
{
    /** @var ?\SensitiveParameterValue RFC 7638 thumbprint of the verifying key. */
    private ?\SensitiveParameterValue $keyThumbprint;

    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  string  $requestId
     * @param  int  $fromTrustVersion
     * @param  int  $toTrustVersion
     * @param  int  $jwksVersion
     * @param  ?string  $keyThumbprint
     * @param  ?string  $algorithm
     */
    public function __construct(

        /** The connection whose keys the refetch replaced. */
        public string $connectionId,

        /** The consumed request whose token triggered the refetch. */
        public string $requestId,

        /** The trust version the request started under. */
        public int $fromTrustVersion,

        /** The trust version the refetch made. */
        public int $toTrustVersion,

        /** The JWKS version the refetch wrote. */
        public int $jwksVersion,

        // Not promoted: held wrapped, since a `kid` may be a thumbprint
        #[\SensitiveParameter]
        ?string $keyThumbprint = null,

        /** The algorithm the token verified under, once known. */
        public ?string $algorithm = null,
    ) {
        $this->keyThumbprint = $keyThumbprint === null ? null : new \SensitiveParameterValue($keyThumbprint);
    }

    /**
     * Show the ids and versions, never the key.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'connection_id'      => $this->connectionId,
            'request_id'         => $this->requestId,
            'from_trust_version' => $this->fromTrustVersion,
            'to_trust_version'   => $this->toTrustVersion,
            'jwks_version'       => $this->jwksVersion,
        ];
    }

    /**
     * Refuse to be serialised; the receipt lives only for its completion.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A transition receipt cannot be serialised.');
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
        throw new \LogicException('A transition receipt cannot be unserialised.');
    }

    /**
     * The RFC 7638 thumbprint of the verifying key, once known.
     *
     * @return ?string
     */
    public function keyThumbprint(): ?string
    {
        /** @var ?string */
        return $this->keyThumbprint?->getValue();
    }

    /**
     * The receipt naming the key and algorithm the token verifies with.
     *
     * @param  string  $thumbprint
     * @param  string  $algorithm
     * @return self
     */
    public function withKey(#[\SensitiveParameter] string $thumbprint, string $algorithm): self
    {
        return new self($this->connectionId, $this->requestId, $this->fromTrustVersion, $this->toTrustVersion, $this->jwksVersion, $thumbprint, $algorithm);
    }
}
