<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Protocols\Enums\CorrelationKind;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * What a protocol driver read from a response to find its authorisation request
 * (SSO-5.1, SSO-5.3, SSO-7.1), before anything in it is validated: the
 * completion pipeline looks the request up and consumes it, the only place a
 * request is consumed, and only then asks the driver to validate the response
 * against it.
 *
 * A solicited response carries the random protocol state (the OIDC `state`, the
 * SAML `RelayState`) and, over SAML, the `InResponseTo` naming the
 * `AuthnRequest` id; at least one of the two is given, and when both are they
 * must name the same request. The state is protocol state, so it is held as a
 * `Secrets\Secret` and only its digest is ever looked up or stored (SSO-9.8).
 * An unsolicited SAML response (SSO-5.8) and an uncorrelated response carry
 * neither.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Correlation
{
    /** @var int The longest SAML request id kept, in bytes. */
    public const int MAX_REQUEST_ID_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Enums\CorrelationKind  $kind
     * @param  ?\SineMacula\Laravel\Sso\Secrets\Secret  $state
     * @param  ?string  $samlRequestId
     */
    private function __construct(

        /** What the response was correlated with. */
        public CorrelationKind $kind,

        /** The protocol state the response carried, for a solicited one that carried it. */
        public ?Secret $state,

        /** The `InResponseTo` a solicited SAML response carried. */
        public ?string $samlRequestId,
    ) {}

    /**
     * The response names a request by its state, its SAML request id, or both.
     *
     * @param  ?string  $state
     * @param  ?string  $samlRequestId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function solicited(#[\SensitiveParameter] ?string $state, ?string $samlRequestId = null): self
    {
        $state         = $state         === '' ? null : $state;
        $samlRequestId = $samlRequestId === '' ? null : $samlRequestId;

        if ($state === null && $samlRequestId === null) {
            throw new \InvalidArgumentException('A solicited response names its request by its state or its SAML request id.');
        }

        if ($samlRequestId !== null && strlen($samlRequestId) > self::MAX_REQUEST_ID_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A SAML request id is at most %d bytes.', self::MAX_REQUEST_ID_LENGTH));
        }

        return new self(CorrelationKind::SOLICITED, $state === null ? null : new Secret($state), $samlRequestId);
    }

    /**
     * An unsolicited SAML response: no `InResponseTo` anywhere.
     *
     * @return self
     */
    public static function unsolicited(): self
    {
        return new self(CorrelationKind::UNSOLICITED, null, null);
    }

    /**
     * Nothing in the response correlates it with a request.
     *
     * @return self
     */
    public static function uncorrelated(): self
    {
        return new self(CorrelationKind::UNCORRELATED, null, null);
    }

    /**
     * The lower-case hex SHA-256 digest of the state, the only form an
     * authorisation request keeps it in, or `null` when the response carried
     * none.
     *
     * @return ?string
     */
    public function stateDigest(): ?string
    {
        return $this->state === null ? null : hash('sha256', $this->state->reveal());
    }

    /**
     * Whether the response names a request.
     *
     * @return bool
     */
    public function isSolicited(): bool
    {
        return $this->kind === CorrelationKind::SOLICITED;
    }

    /**
     * Whether the response is an unsolicited SAML response.
     *
     * @return bool
     */
    public function isUnsolicited(): bool
    {
        return $this->kind === CorrelationKind::UNSOLICITED;
    }

    /**
     * Whether nothing in the response correlates it with a request.
     *
     * @return bool
     */
    public function isUncorrelated(): bool
    {
        return $this->kind === CorrelationKind::UNCORRELATED;
    }
}
