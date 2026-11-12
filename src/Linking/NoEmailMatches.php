<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;

/**
 * The default link email contract: it matches no identity, so nothing links by
 * domain.
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
