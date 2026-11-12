<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlAdapter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Envelope;

/**
 * Reads which authorisation request a SAML response answers, validating
 * nothing; what it reads is trusted only once validation verifies it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResponseCorrelator
{
    /** @var int The longest `RelayState` the package sends, and so accepts, in bytes. */
    public const int MAX_RELAY_STATE_BYTES = 80;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlAdapter  $adapter
     */
    public function __construct(

        /** Reads the response's envelope. */
        private SamlAdapter $adapter,
    ) {}

    /**
     * Read what the response names.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     *
     * @throws \InvalidArgumentException
     */
    public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
    {
        unset($connection);

        $encoded  = self::posted($request);
        $envelope = $encoded === null ? null : $this->adapter->envelope($encoded);

        return $envelope === null ? Correlation::uncorrelated() : self::correlation($envelope, $request->body()['RelayState'] ?? null);
    }

    /**
     * The posted `SAMLResponse`, if an HTTP-POST carries it as a non-empty
     * string.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return ?string
     */
    private static function posted(CompletionRequest $request): ?string
    {
        $encoded = $request->body()['SAMLResponse'] ?? null;

        return $request->method === 'POST' && is_string($encoded) && $encoded !== '' ? $encoded : null;
    }

    /**
     * What the envelope names, with the posted `RelayState`. Any `InResponseTo`
     * keeps a response from being unsolicited.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Envelope  $envelope
     * @param  mixed  $relayState
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     *
     * @throws \InvalidArgumentException
     */
    private static function correlation(Envelope $envelope, #[\SensitiveParameter] mixed $relayState): Correlation
    {
        $requestId = $envelope->requestId();

        return match (true) {
            $envelope->isUnsolicited()     => Correlation::unsolicited(),
            !self::isRequestId($requestId) => Correlation::uncorrelated(),
            default                        => Correlation::solicited(self::relayState($relayState), $requestId),
        };
    }

    /**
     * Whether the id is non-empty and fits a stored SAML request id.
     *
     * @param  ?string  $requestId
     * @return bool
     *
     * @phpstan-assert-if-true non-empty-string $requestId
     */
    private static function isRequestId(?string $requestId): bool
    {
        return $requestId !== null && $requestId !== '' && strlen($requestId) <= Correlation::MAX_REQUEST_ID_LENGTH;
    }

    /**
     * The `RelayState` if it is a short enough string; otherwise `null`, which
     * the consumed request refuses with `request_mismatch`.
     *
     * @param  mixed  $relayState
     * @return ?string
     */
    private static function relayState(#[\SensitiveParameter] mixed $relayState): ?string
    {
        return is_string($relayState) && strlen($relayState) <= self::MAX_RELAY_STATE_BYTES ? $relayState : null;
    }
}
