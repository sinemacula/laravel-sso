<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Domains\DnsLookup;

/**
 * DNS resolver contract (SSO-3.2, SSO-3.3, decision D3): looks up the TXT
 * records at a name, for the verification of a claimed domain and the scheduled
 * rechecks of verified ones.
 *
 * It answers one of three outcomes as a `Domains\DnsLookup`: `found` with every
 * TXT record at the name (each record's character-strings joined), `absent`
 * when the name has none or does not exist, and `lookup_failed` when it could
 * not tell (a timeout, a server failure, a refusal). It must never answer
 * `absent` or a record when it could not tell: the package reads `absent` as
 * the record having gone, and `lookup_failed` as nothing proven either way.
 *
 * The default, `Domains\SystemDnsResolver`, asks the system resolver through
 * `dns_get_record()`, which has no timeout of its own. An application that
 * needs a bounded deadline, DNSSEC validation or DNS over HTTPS binds its own.
 * `Testing\FakeDnsResolver` answers what a test gives it.
 *
 * The name is lower-case ASCII with no trailing dot, as the package builds it.
 * An implementation resolves it as absolute, never expanding it with a search
 * list or appending a search domain, so the answer is always for the name
 * asked. An implementation keeps nothing of one lookup for the next (SSO-11.2),
 * and never logs or reports a record's value beyond the lookup's outcome.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface DnsResolver
{
    /**
     * The TXT records at the name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Domains\DnsLookup
     */
    public function txt(string $name): DnsLookup;
}
