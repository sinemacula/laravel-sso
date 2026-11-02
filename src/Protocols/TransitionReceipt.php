<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

/**
 * What lets one sign-in finish across the key rotation its own token triggered
 * (SSO-2.13, SSO-7.3, `docs/design/flows.md`): when a callback's unknown-`kid`
 * refetch commits a JWKS that removes a key, the trust version is raised and
 * everything in flight through the connection is voided, except the one
 * consumed request whose token asked. The refetch answers this receipt, naming
 * exactly that connection, that request, the trust version it left and the one
 * it made, and the JWKS version it wrote. The key the token then verified with
 * is added (`withKey()`), and a driver hands the receipt on only once every
 * check of the token has passed under those keys.
 *
 * `Metadata\TransitionReceipts::permits()` judges it at the final locks. It
 * never restores a request voided independently and never adopts a later trust
 * version: anything but this exact transition refuses the completion.
 *
 * It lives only for the completion that got it: it is never stored, so it
 * cannot carry into another request, and it refuses to be serialised or
 * unserialised. A dump shows the versions alone.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TransitionReceipt
{
    /** @var ?\SensitiveParameterValue The RFC 7638 thumbprint of the key the token verified with, once known; held wrapped, since a `kid` may be one. */
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

        /** The trust version the request was started under, which the refetch left. */
        public int $fromTrustVersion,

        /** The trust version the refetch made. */
        public int $toTrustVersion,

        /** The JWKS version the refetch wrote. */
        public int $jwksVersion,

        // Not promoted: held wrapped, so no dump, export or array cast shows it
        #[\SensitiveParameter]
        ?string $keyThumbprint = null,

        /** The algorithm the token verified under, once known. */
        public ?string $algorithm = null,
    ) {
        $this->keyThumbprint = $keyThumbprint === null ? null : new \SensitiveParameterValue($keyThumbprint);
    }

    /**
     * What a dump shows: the ids and the versions, never the key.
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
     * Refuse to be serialised: the receipt lives only for its completion.
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
     * The RFC 7638 thumbprint of the key the token verified with, once known.
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
