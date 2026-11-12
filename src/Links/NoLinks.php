<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The default linker: nothing resolves, and nothing writes a link while it is
 * bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoLinks implements Linker
{
    /**
     * Resolve nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     */
    #[\Override]
    public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
    {
        unset($result, $client);

        return LinkResolution::absent();
    }
}
