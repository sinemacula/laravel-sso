<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam\Contracts;

/**
 * A stand-in for `laravel-authentication`'s link contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface ExternalIdentityLinks
{
    /**
     * The link the connection, issuer and subject resolve to, or `null`.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @return ?string
     */
    public function find(string $connectionId, string $issuer, string $subject): ?string;
}
