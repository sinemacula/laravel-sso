<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * Resolves a host name for the outbound fetcher (SSO-2.9), once per request and
 * redirect: the fetcher checks every address it answers and pins the connection
 * to the first, so the name is never resolved a second time.
 *
 * The default, `Fetching\SystemHostResolver`, is bound in the container as a
 * singleton and asks the system resolver, which has no timeout control and
 * which PHP cannot interrupt. The fetcher counts each lookup against the
 * fetch's one deadline and checks it straight after, failing the fetch as a
 * timeout when the lookup ran past it, but it cannot cut a lookup short. An
 * application that needs a bounded lookup, DNSSEC or DNS over HTTPS binds its
 * own implementation in the container, and the default fetcher resolves it from
 * there; a bounded implementation answers `[]` when its own time runs out.
 *
 * An implementation answers every A and AAAA address of the name as an IP
 * literal, and `[]` when the name has none or cannot be resolved; it never
 * throws for a name that does not resolve. Anything it answers that is not an
 * IP literal is refused by the fetcher, never connected to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HostResolver
{
    /**
     * Every A and AAAA address of the host name, `[]` when there is none.
     *
     * @param  string  $asciiHost
     * @return list<string>
     */
    public function addresses(string $asciiHost): array;
}
