<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Reinitiation;

/**
 * A protocol driver that answers an unsolicited response by re-initiation
 * (SSO-5.8): the SAML driver. When its `correlate()` reads a response as
 * unsolicited, the completion asks `reinitiate()` instead of consuming a
 * request, which validates the response by the unsolicited profile (SSO-6.11)
 * against what the connection holds, outside any transaction, and answers the
 * start URL and the replay record, or a refusal.
 *
 * It never touches the package's storage, never consumes a request and never
 * signs anyone in: the completion records the response against replay, under
 * the connection's lock with the connection checked again, and answers with the
 * start URL. A connection that does not allow IdP-initiated sign-in is refused
 * with `unsolicited_not_allowed`. Under the lock the completion asks
 * `startUrl()` of the locked connection again, so an opt-in turned off or a
 * start URL changed while the response was validated refuses it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ReinitiatingDriver
{
    /**
     * Validate the unsolicited response at the connection's endpoint, and
     * answer where re-initiation sends the browser, or why it is refused.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Reinitiation
     */
    public function reinitiate(SsoConnection $connection, CompletionRequest $request): Reinitiation;

    /**
     * Where re-initiation sends the browser for the connection as given, or
     * `null` when it takes no unsolicited response; read from what the
     * connection holds, with nothing logged.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return ?string
     */
    public function startUrl(SsoConnection $connection): ?string;
}
