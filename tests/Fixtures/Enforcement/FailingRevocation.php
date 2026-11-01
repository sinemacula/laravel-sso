<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enforcement;

use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * A session revocation that cannot revoke: it counts the call and throws, as an
 * adapter signals failure, so a test proves the change it was called for rolls
 * back and the exception propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingRevocation implements SessionRevocation
{
    /** @var string The message of the exception every call throws. */
    public const string MESSAGE = 'The sessions could not be revoked.';

    /** @var int How many times it was called. */
    private int $calls = 0;

    /**
     * Count the call and fail.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        $this->calls++;

        throw new \RuntimeException(self::MESSAGE);
    }

    /**
     * How many times it was called.
     *
     * @return int
     */
    public function calls(): int
    {
        return $this->calls;
    }
}
