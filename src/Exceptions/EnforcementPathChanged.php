<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Exceptions;

/**
 * A tenant's enforcement inheritance path changed before it was locked; retry
 * the whole transaction.
 *
 * Its code is SQLSTATE 40001 as an integer, which Laravel retries as a
 * serialisation failure and keeps when it rethrows from a nested level.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class EnforcementPathChanged extends \PDOException
{
    /**
     * The refusal of a transaction whose inheritance path changed.
     *
     * @return self
     */
    public static function retryWhole(): self
    {
        return new self('A tenant\'s enforcement inheritance path changed before it was locked; retry the whole transaction.', 40001);
    }
}
