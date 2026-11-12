<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

/**
 * Thrown when authentication refuses the sign-in, so the redemption's
 * transaction rolls back and the code stays unspent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExternalSignInRefused extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \Tests\Integration\Examples\IntegratingWithLaravelIam\SignInResult  $result
     */
    public function __construct(

        /** The refusal authentication answered. */
        public readonly SignInResult $result,
    ) {
        parent::__construct('Authentication refused the external sign-in: ' . $result->reason . '.');
    }
}
