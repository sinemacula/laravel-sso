<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Protocols\Enums\CorrelationKind;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * What a driver read from a response to find its authorisation request, before
 * validation. The state is a secret; only its digest is looked up or stored.
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

        /** The OIDC `state` or SAML `RelayState`, if carried. */
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
     * The lower-case hex SHA-256 digest of the state, or `null` without one.
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
