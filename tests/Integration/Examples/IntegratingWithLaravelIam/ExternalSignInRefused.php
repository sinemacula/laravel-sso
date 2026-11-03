<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

/**
 * The adapter's report of a sign-in authentication refused
 * (`docs/guides/integrating-with-laravel-iam.md`): thrown out of the
 * redemption's transaction, so the consumption rolls back with it and the code
 * stays unspent.
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
