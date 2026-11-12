<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;

/**
 * Finds the identities whose verified email equals the linking email, for
 * linking by a verified domain.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkEmailMatcher
{
    /**
     * Read from the write connection and never log the email; an answer that
     * cannot be vouched for is never `exactly one`.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\LinkEmailQuery  $query
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     */
    public function match(LinkEmailQuery $query): LinkEmailMatch;
}
