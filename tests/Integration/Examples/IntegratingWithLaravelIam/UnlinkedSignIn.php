<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

/**
 * The adapter's refusal of an admitted sign-in that established no identity
 * (`docs/guides/integrating-with-laravel-iam.md`): the adapter always requires
 * a linked identity, so it throws this out of the redemption's transaction,
 * which rolls the consumption back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnlinkedSignIn extends \RuntimeException
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct('The sign-in established no linked identity, which the adapter requires.');
    }
}
