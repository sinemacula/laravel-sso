<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Resolves a verified result to a link by its connection, issuer and subject.
 *
 * A resolution can write, so a caller inside its own transaction locks the
 * result's connection first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Linker
{
    /**
     * Match only within the result's own connection, and never answer an
     * identity that cannot be vouched for.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     */
    public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution;
}
