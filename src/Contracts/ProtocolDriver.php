<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;

/**
 * One identity protocol, registered on `Protocols\ProtocolManager` by name.
 *
 * Hold no state between calls and never touch the package's storage; answer
 * expected refusals as values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ProtocolDriver
{
    /**
     * Type the values as this protocol's settings.
     *
     * @param  array<array-key, mixed>  $values
     * @return \SineMacula\Laravel\Sso\Contracts\ProtocolSettings
     */
    public function settings(array $values): ProtocolSettings;

    /**
     * Whether the connection's settings, secrets and keys are all present.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     */
    public function isComplete(SsoConnection $connection): bool;

    /**
     * Start an authorisation request at the identity provider, or refuse.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     */
    public function start(SsoConnection $connection, StartRequest $request): Start;

    /**
     * Read which request the response answers, validating nothing else; the
     * pipeline consumes that request before `complete()` runs.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     */
    public function correlate(SsoConnection $connection, CompletionRequest $request): Correlation;

    /**
     * Validate the response against the consumed request, or refuse. Any event
     * the validation records carries the client.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  \SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    public function complete(SsoConnection $connection, CompletionRequest $request, ConsumedRequest $consumed, ClientContext $client): Completion;

    /**
     * What an administrator registers at the identity provider, with no secret.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Protocols\ServiceProviderDescription
     */
    public function describe(SsoConnection $connection): ServiceProviderDescription;
}
