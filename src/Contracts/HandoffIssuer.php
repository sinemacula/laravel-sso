<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;

/**
 * Issues the single-use, short-lived code that carries a verified result to the
 * client that started the flow, bound to every part of the grant.
 *
 * Called inside the completion's transaction on the storage connection; write
 * there, or the issue is not atomic with the completion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HandoffIssuer
{
    /**
     * Store the code as a hash with the grant's trust version, session deadline
     * and reservation in one write; throw on failure.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffGrant  $grant
     * @return \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff
     */
    public function issue(HandoffGrant $grant): IssuedHandoff;
}
