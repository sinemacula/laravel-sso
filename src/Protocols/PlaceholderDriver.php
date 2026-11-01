<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * A package protocol registered before its flows are built: it reads its
 * protocol's settings, and fails every flow closed. No connection over it is
 * ever complete, so none is usable; a start or a completion is refused with
 * `connection_unavailable`, and the service provider side cannot be described.
 *
 * The SAML driver (P4) and the OIDC driver (P5) replace it as they land; until
 * then a connection over either can be created and configured, and nothing can
 * sign in through it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class PlaceholderDriver implements ProtocolDriver
{
    /**
     * The settings the values give, typed by the protocol's settings class.
     *
     * @param  array<array-key, mixed>  $values
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
     *
     * @throws \LogicException
     */
    #[\Override]
    public function settings(array $values): ProtocolSettings
    {
        $class = $this->settingsClass();

        if (!is_a($class, ProtocolSettings::class, true)) {
            throw new \LogicException(sprintf('The settings of the [%s] protocol are not available.', static::class));
        }

        return $class::fromArray($values);
    }

    /**
     * No connection over a placeholder is complete, so none is used.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     */
    #[\Override]
    public function isComplete(SsoConnection $connection): bool
    {
        unset($connection);

        return false;
    }

    /**
     * Refuse to start: the protocol's flows are not built.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     */
    #[\Override]
    public function start(SsoConnection $connection, StartRequest $request): Start
    {
        unset($connection, $request);

        return Start::refused(FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * Refuse every response: the protocol's validation is not built.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    #[\Override]
    public function complete(SsoConnection $connection, CompletionRequest $request): Completion
    {
        unset($connection, $request);

        return Completion::refused(FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * Describe nothing: the protocol's service provider side is not built.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    #[\Override]
    public function describe(SsoConnection $connection): ServiceProviderDescription
    {
        unset($connection);

        return ServiceProviderDescription::unavailable(FailureReason::CONNECTION_UNAVAILABLE);
    }

    /**
     * The fully qualified name of the protocol's settings class, which
     * implements `Contracts\ProtocolSettings`.
     *
     * @return string
     */
    abstract protected function settingsClass(): string;
}
