<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;

/**
 * The default link email contract (SSO-8.8): it finds no identity, so nothing
 * is linked by a verified domain until the application binds its own.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoEmailMatches implements LinkEmailMatcher
{
    /**
     * Match nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\LinkEmailQuery  $query
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     */
    #[\Override]
    public function match(LinkEmailQuery $query): LinkEmailMatch
    {
        unset($query);

        return LinkEmailMatch::none();
    }
}
