<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

/**
 * Thrown for an admitted sign-in with no linked identity, so the redemption's
 * transaction rolls back.
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
