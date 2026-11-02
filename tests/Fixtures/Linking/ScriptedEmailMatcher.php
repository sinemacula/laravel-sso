<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Linking;

use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;

/**
 * A link email contract answering what the test sets, or throwing it, and
 * recording the queries it was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedEmailMatcher implements LinkEmailMatcher
{
    /** @var list<\SineMacula\Laravel\Sso\Linking\LinkEmailQuery> Every query asked. */
    public array $queries = [];

    /** @var ?\Throwable What it throws instead of answering. */
    public ?\Throwable $failure = null;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\LinkEmailMatch  $match
     */
    public function __construct(

        /** What it answers. */
        public LinkEmailMatch $match,
    ) {}

    /**
     * Answer the match set.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\LinkEmailQuery  $query
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     *
     * @throws \Throwable
     */
    #[\Override]
    public function match(LinkEmailQuery $query): LinkEmailMatch
    {
        $this->queries[] = $query;

        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->match;
    }
}
