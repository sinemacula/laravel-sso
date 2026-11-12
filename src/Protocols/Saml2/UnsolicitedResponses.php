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
 * Validates an unsolicited SAML response for re-initiation. The posted
 * `RelayState` is never read, so it can never become a redirect target.
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

        /** The package's sanitising logger. */
        private LoggerInterface $logger,
    ) {}

    /**
     * Validate the response by the unsolicited profile.
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
     * The start URL naming the connection, or `null` when re-initiation is off
     * or there is no start URL. Logs nothing.
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
     * The start URL, or why the connection takes no unsolicited response.
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
     * The URL with the `connection` query parameter appended.
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
