<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Evidence;

use Carbon\CarbonImmutable;

/**
 * The authentication evidence the evidence contract accepted; not an assurance
 * level.
 *
 * Provider values are wrapped, redacted in dumps and refuse serialisation.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AcceptedEvidence implements \JsonSerializable
{
    /** @var \SensitiveParameterValue The accepted RFC 8176 `amr` values. */
    private \SensitiveParameterValue $methods;

    /** @var \SensitiveParameterValue The raw `acr` or `AuthnContextClassRef`. */
    private \SensitiveParameterValue $rawContext;

    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  list<string>  $methods
     * @param  ?string  $rawContext
     */
    public function __construct(

        /** The connection, as the credential reference. */
        public string $connectionId,

        /** When the provider authenticated the person. */
        public CarbonImmutable $authenticatedAt,

        // The accepted RFC 8176 `amr` values; held wrapped
        #[\SensitiveParameter]
        array $methods = [],

        // The raw `acr` or `AuthnContextClassRef`; held wrapped
        #[\SensitiveParameter]
        ?string $rawContext = null,
    ) {
        $this->methods    = new \SensitiveParameterValue($methods);
        $this->rawContext = new \SensitiveParameterValue($rawContext);
    }

    /**
     * What a dump shows: the connection, the time and how many methods.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    /**
     * Refuse to be serialised: it holds provider values.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('Accepted evidence cannot be serialised.');
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
        throw new \LogicException('Accepted evidence cannot be unserialised.');
    }

    /**
     * The accepted RFC 8176 `amr` values.
     *
     * @return list<string>
     */
    public function methods(): array
    {
        /** @var list<string> */
        return $this->methods->getValue();
    }

    /**
     * The raw `acr` or `AuthnContextClassRef`, as data.
     *
     * @return ?string
     */
    public function rawContext(): ?string
    {
        /** @var ?string */
        return $this->rawContext->getValue();
    }

    /**
     * The redacted form: counts and presence, never provider values.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'connection_id'    => $this->connectionId,
            'authenticated_at' => $this->authenticatedAt->utc()->format('Y-m-d\TH:i:s\Z'),
            'methods'          => count($this->methods()),
            'raw_context'      => $this->rawContext() === null ? null : '[redacted]',
        ];
    }
}
