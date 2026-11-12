<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Reinitiation;

/**
 * A protocol driver that answers an unsolicited response by re-initiating a
 * flow, as the SAML driver does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ReinitiatingDriver
{
    /**
     * Validate the unsolicited response without touching storage or a
     * transaction, and answer the start URL or a refusal.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Reinitiation
     */
    public function reinitiate(SsoConnection $connection, CompletionRequest $request): Reinitiation;

    /**
     * The re-initiation URL, or `null` when the connection takes no unsolicited
     * response; asked again under the connection's lock.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return ?string
     */
    public function startUrl(SsoConnection $connection): ?string;
}
