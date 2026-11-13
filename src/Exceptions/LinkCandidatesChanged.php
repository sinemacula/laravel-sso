<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Exceptions;

/**
 * An identity's domain links changed before they were locked; retry the whole
 * transaction.
 *
 * Locking the new connection now would break the lock order, so nothing is
 * written. Its code is SQLSTATE 40001 as an integer, which Laravel retries as a
 * serialisation failure and keeps when it rethrows from a nested level.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LinkCandidatesChanged extends \PDOException
{
    /**
     * The refusal of a transaction whose candidates changed.
     *
     * @return self
     */
    public static function retryWhole(): self
    {
        return new self('An identity\'s verified domain links changed before they were locked; retry the whole transaction.', 40001);
    }
}
