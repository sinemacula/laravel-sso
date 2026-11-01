<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The default linking contract (SSO-8.3): no result resolves to an identity, so
 * every `sign_in` result is unlinked until the application binds the link
 * store, `laravel-iam` binds it, or the application binds its own.
 *
 * It holds nothing between calls (SSO-11.2).
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
     * @return ?\SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    #[\Override]
    public function resolve(VerifiedResult $result): ?IdentityReference
    {
        unset($result);

        return null;
    }
}
