<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * Resolves a host name for the outbound fetcher, which checks every address and
 * pins the connection to the first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HostResolver
{
    /**
     * Answer every A and AAAA address as an IP literal, and `[]` rather than
     * throw when the name does not resolve or a bounded lookup times out.
     *
     * @param  string  $asciiHost
     * @return list<string>
     */
    public function addresses(string $asciiHost): array;
}
