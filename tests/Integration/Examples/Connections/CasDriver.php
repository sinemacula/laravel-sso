<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Connections;

use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;

/**
 * The example application's own protocol driver (SSO-2.2), registered as `cas`:
 * a connection is complete once its CAS server is set, a flow starts by sending
 * the browser to the server's login page with the connection's callback as the
 * service, carrying the request's `state`, and a response is correlated by that
 * `state`. Validating the service ticket at the server is left out of the
 * example, so every response is refused; a real driver validates it there, and
 * answers what it verified.
 *
 * It holds nothing between calls (SSO-11.2): the registry keeps one instance
 * per request or job, and the connection, its settings and the request are
 * given to each call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CasDriver implements ProtocolDriver
{
    /**
     * The CAS settings the values give.
     *
     * @param  array<array-key, mixed>  $values
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
     */
    #[\Override]
    public function settings(array $values): ProtocolSettings
    {
        return CasSettings::fromArray($values);
    }

    /**
     * Complete once the CAS server is set, over HTTPS.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     */
    #[\Override]
    public function isComplete(SsoConnection $connection): bool
    {
        return $this->settings($connection->getSettings())->isComplete();
    }

    /**
     * Send the browser to the CAS server's login page, with the connection's
     * callback, carrying the request's `state`, as the service.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     */
    #[\Override]
    public function start(SsoConnection $connection, StartRequest $request): Start
    {
        $server = CasSettings::fromArray($connection->getSettings())->serverUrl();

        if ($server === null) {
            return Start::refused(FailureReason::CONNECTION_UNAVAILABLE);
        }

        $service = self::callback($connection) . '?' . http_build_query(['state' => $request->state->reveal()]);

        return Start::navigate(Navigation::redirect($server . '/login?' . http_build_query(['service' => $service])));
    }

    /**
     * Correlate a response by the `state` its service URL carries back.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     */
    #[\Override]
    public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation
    {
        unset($connection);

        parse_str($request->query(), $query);

        $state = $query['state'] ?? null;

        return is_string($state) && $state !== '' ? Correlation::solicited($state) : Correlation::uncorrelated();
    }

    /**
     * Refuse the response: the example does not validate the service ticket.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    #[\Override]
    public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed): Completion
    {
        unset($connection, $request, $consumed);

        return Completion::refused(FailureReason::PROVIDER_ERROR);
    }

    /**
     * The service URL an administrator registers at the CAS server, as JSON.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    #[\Override]
    public function describe(SsoConnection $connection): ServiceProviderDescription
    {
        return ServiceProviderDescription::document('application/json', (string) json_encode(['service' => self::callback($connection)]));
    }

    /**
     * The connection's callback, which the CAS server sends the browser back
     * to.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return string
     */
    private static function callback(SsoConnection $connection): string
    {
        return app(EndpointResolver::class)->endpoints($connection)->callback;
    }
}
