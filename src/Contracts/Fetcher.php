<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;

/**
 * Sends every outbound request to an administrator- or provider-supplied
 * address.
 *
 * An implementation must keep the rules in `docs/design/outbound-requests.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Fetcher
{
    /**
     * Answer a refusal or failure as a result, never an exception.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    public function fetch(FetchRequest $request): FetchResult;
}
