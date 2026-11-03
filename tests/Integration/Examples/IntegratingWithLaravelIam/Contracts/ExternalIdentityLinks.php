<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam\Contracts;

/**
 * A stand-in for `laravel-authentication`'s link contract (its PR #127), which
 * this package does not install: the link a connection, an issuer and a subject
 * resolve to, which authentication asks before it signs anyone in, and which
 * the adapter answers from the redemption it admitted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface ExternalIdentityLinks
{
    /**
     * The id of the link the connection, the issuer and the subject resolve to,
     * or `null` when none does.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @return ?string
     */
    public function find(string $connectionId, string $issuer, string $subject): ?string;
}
