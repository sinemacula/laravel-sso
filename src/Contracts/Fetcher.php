<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;

/**
 * Fetcher contract (SSO-2.9): every outbound request to an address an
 * administrator entered, or that metadata or discovery supplied (metadata,
 * discovery, JWKS, token and UserInfo endpoints), goes through it.
 *
 * Whatever its transport, an implementation:
 *
 * - allows only `https`, and verifies the server's certificate and host name
 *   even though it connects to a checked address;
 * - resolves the host, refuses loopback, private, link-local, unique-local,
 *   multicast and cloud metadata addresses (IPv4 and IPv6, mapped forms
 *   included), and any range the application adds, and connects to the address
 *   it checked, so a second resolution cannot change it;
 * - follows no redirect for a request that carries a credential, and checks
 *   each redirect of any other request the same way;
 * - caps the response's size and the time taken;
 * - sends the request's one credential as its kind says, and no other.
 *
 * A refused or failed request is a result (`fetch_refused`, `fetch_failed`),
 * never an exception, and its detail goes only to the logs, without the
 * request's form, credential or the response's body. An application may bind
 * its own fetcher (to use an egress proxy, say) that keeps these rules.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Fetcher
{
    /**
     * Send the request, or refuse it.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    public function fetch(FetchRequest $request): FetchResult;
}
