<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Reinitiation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;

/**
 * Validates an unsolicited SAML response by the unsolicited profile (SSO-5.8,
 * SSO-6.11) for a connection that allows IdP-initiated sign-in, and answers the
 * connection's start URL and the replay record of its assertion.
 *
 * - A connection whose `idp_initiated` is off (the default) refuses every
 *   unsolicited response with `unsolicited_not_allowed`, before anything in it
 *   is read, and logs that it did, naming the connection alone.
 * - One that is on but holds no `idp_initiated_start_url` is incomplete, so it
 *   is refused with `connection_unavailable`; the settings never store such a
 *   connection, so this only fails closed.
 * - Otherwise the response is held to every rule of a successful response
 *   (`Validation\AssertionValidator`, with no consumed request): signatures,
 *   issuers, destination, encryption, conditions, audiences, the bearer
 *   confirmation, the subject and the authentication context. An `InResponseTo`
 *   anywhere, inside an encrypted assertion included, makes it solicited, which
 *   with no request is `request_unknown`; an unsuccessful status is
 *   `provider_error`. A refusal keeps the validator's reason.
 * - A response that passes is allowed: the start URL with the query parameter
 *   `connection` set to the connection's id, added after a `?`, or after an `&`
 *   when the URL already has a query, and the replay record of its assertion,
 *   which the completion records under the connection's lock.
 *
 * The posted `RelayState` is never read, so it can never become a redirect
 * target (SSO-5.8); the response's subject and attributes go no further than
 * the validator. Nothing of the response is logged, reported or kept. It holds
 * the validator and the sanitising logger, neither of which keeps anything
 * between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UnsolicitedResponses
{
    /** @var string The query parameter of the start URL that names the connection. */
    public const string CONNECTION_PARAMETER = 'connection';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator  $validator
     * @param  \Psr\Log\LoggerInterface  $logger
     */
    public function __construct(

        /** Validates the response by the unsolicited profile. */
        private AssertionValidator $validator,

        /** Logs a response refused for a connection that does not allow it; the package's sanitising logger. */
        private LoggerInterface $logger,
    ) {}

    /**
     * Validate the unsolicited response and answer where re-initiation sends
     * the browser.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Reinitiation
     *
     * @throws \InvalidArgumentException
     */
    public function reinitiate(SsoConnection $connection, Saml2Options $options, CompletionRequest $request): Reinitiation
    {
        $startUrl = $this->allowed($connection, $options);

        if ($startUrl instanceof FailureReason) {
            return Reinitiation::refused($startUrl);
        }

        $completion = $this->validator->validate($connection, $options, $request, null);
        $replay     = $completion->replay;

        return $replay === null ? Reinitiation::refused($completion->reason ?? FailureReason::RESPONSE_INVALID) : Reinitiation::allowed($startUrl, $replay);
    }

    /**
     * The start URL naming the connection, or `null` when the connection does
     * not allow IdP-initiated sign-in or holds no start URL; nothing is logged.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @return ?string
     */
    public function startUrl(SsoConnection $connection, Saml2Options $options): ?string
    {
        $startUrl = $options->idpInitiatedStartUrl;

        if ($startUrl === null || !$options->isOn(Saml2Setting::IDP_INITIATED)) {
            return null;
        }

        return self::naming($startUrl, $connection->getConnectionId());
    }

    /**
     * The start URL naming the connection, or why the connection takes no
     * unsolicited response.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @return \SineMacula\Laravel\Sso\Events\Enums\FailureReason|string
     */
    private function allowed(SsoConnection $connection, Saml2Options $options): FailureReason|string
    {
        if (!$options->isOn(Saml2Setting::IDP_INITIATED)) {

            $this->logger->notice('sso.saml2.unsolicited_not_allowed', ['connection_id' => $connection->getConnectionId()]);

            return FailureReason::UNSOLICITED_NOT_ALLOWED;
        }

        return $this->startUrl($connection, $options) ?? FailureReason::CONNECTION_UNAVAILABLE;
    }

    /**
     * The URL with the `connection` query parameter added, its value encoded:
     * after a `?` when it has no query, directly when it ends its query with a
     * `?` or an `&`, and after an `&` otherwise.
     *
     * @param  string  $url
     * @param  string  $connectionId
     * @return string
     */
    private static function naming(string $url, string $connectionId): string
    {
        $separator = match (true) {
            !str_contains($url, '?')                           => '?',
            str_ends_with($url, '?'), str_ends_with($url, '&') => '',
            default                                            => '&',
        };

        return $url . $separator . http_build_query([self::CONNECTION_PARAMETER => $connectionId], '', '&', PHP_QUERY_RFC3986);
    }
}
