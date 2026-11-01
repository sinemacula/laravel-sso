<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlAdapter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Envelope;

/**
 * Reads which authorisation request a SAML response at the connection's
 * assertion consumer service answers (SSO-5.3, SSO-5.8), validating nothing:
 * the completion looks the request up by the connection and its SAML request
 * id, consumes it, and compares the `RelayState`'s digest with the request's
 * state digest, before anything in the response is validated.
 *
 * - Only an HTTP-POST whose `SAMLResponse` field is a non-empty string is read
 *   (`SamlAdapter::envelope()`); any other method, a missing, empty or
 *   array-shaped field, or an envelope that cannot be read is uncorrelated.
 * - A response with no `InResponseTo` anywhere is unsolicited (SSO-5.8). One
 *   whose `InResponseTo` values disagree, or name an id that is empty or longer
 *   than `Correlation::MAX_REQUEST_ID_LENGTH`, is uncorrelated: an
 *   `InResponseTo` anywhere keeps a response from being unsolicited.
 * - Otherwise it is solicited, naming the one request id, with its `RelayState`
 *   when that is a string of at most 80 bytes; a `RelayState` that is missing,
 *   longer or array-shaped is left out, so the consumed request refuses the
 *   response with `request_mismatch`.
 *
 * Nothing here validates, logs or keeps anything (SSO-11.2); every value it
 * reads is trusted only once the response validation has verified it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResponseCorrelator
{
    /** @var int The longest `RelayState` the package sends, and so accepts, in bytes (SSO-5.3). */
    public const int MAX_RELAY_STATE_BYTES = 80;

    /** @var string The only method the assertion consumer service reads. */
    private const string METHOD = 'POST';

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
     * The posted `SAMLResponse`, when the request is an HTTP-POST carrying it
     * as a non-empty string.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return ?string
     */
    private static function posted(CompletionRequest $request): ?string
    {
        $encoded = $request->body()['SAMLResponse'] ?? null;

        return $request->method === self::METHOD && is_string($encoded) && $encoded !== '' ? $encoded : null;
    }

    /**
     * What the envelope names, with the `RelayState` posted beside it.
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
     * Whether the id is one a request can carry: non-empty and no longer than a
     * stored SAML request id.
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
     * The `RelayState`, when it is a string of at most 80 bytes.
     *
     * @param  mixed  $relayState
     * @return ?string
     */
    private static function relayState(#[\SensitiveParameter] mixed $relayState): ?string
    {
        return is_string($relayState) && strlen($relayState) <= self::MAX_RELAY_STATE_BYTES ? $relayState : null;
    }
}
