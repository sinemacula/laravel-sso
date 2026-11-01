<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Protocols;

use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;

/**
 * A protocol an application might register: complete once its issuer is set, it
 * starts by redirecting to the issuer, refuses every completion, and describes
 * itself as a small JSON document.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExampleDriver implements ProtocolDriver
{
    /**
     * The example settings the values give.
     *
     * @param  array<array-key, mixed>  $values
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
     */
    #[\Override]
    public function settings(array $values): ProtocolSettings
    {
        return ExampleSettings::fromArray($values);
    }

    /**
     * Complete once the issuer is set.
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
     * Redirect to the issuer.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     */
    #[\Override]
    public function start(SsoConnection $connection, StartRequest $request): Start
    {
        $issuer = $connection->getSettings()['issuer'] ?? null;

        return is_string($issuer) ? Start::navigate(Navigation::redirect($issuer), ['reference' => $request->reference]) : Start::refused(FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * Refuse every response.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    #[\Override]
    public function complete(SsoConnection $connection, CompletionRequest $request): Completion
    {
        unset($connection, $request);

        return Completion::refused(FailureReason::PROVIDER_ERROR);
    }

    /**
     * A JSON document naming the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    #[\Override]
    public function describe(SsoConnection $connection): ServiceProviderDescription
    {
        return ServiceProviderDescription::document('application/json', (string) json_encode(['connection' => $connection->getConnectionId()]));
    }
}
