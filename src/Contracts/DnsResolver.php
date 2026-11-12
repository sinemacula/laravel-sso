<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Domains\DnsLookup;

/**
 * Looks up TXT records for domain verification and rechecks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface DnsResolver
{
    /**
     * Resolve the name as absolute, and answer `lookup_failed`, never `absent`,
     * when the lookup could not tell.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Domains\DnsLookup
     */
    public function txt(string $name): DnsLookup;
}
