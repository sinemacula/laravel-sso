<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Links;

use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * A linker that resolves every result to one identity, or to nothing, through a
 * link whose id `ExampleLinks` gives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedLinker implements Linker
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     */
    public function __construct(

        /** What every result resolves to. */
        private ?IdentityReference $identity,
    ) {}

    /**
     * Resolve the result to the identity.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     */
    #[\Override]
    public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
    {
        unset($result);

        return ExampleLinks::resolution($this->identity);
    }
}
