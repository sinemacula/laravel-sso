<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Before;

/**
 * Turns PHP warnings and notices into errors for tests that skip the framework.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait TreatsWarningsAsErrors
{
    /**
     * Throw on a warning or notice, except one silenced with `@`, which shows
     * as a reporting level other than the one PHPUnit set for the test.
     *
     * @return void
     */
    #[Before]
    protected function treatWarningsAsErrors(): void
    {
        $reporting = error_reporting();

        set_error_handler(static function (int $severity, string $message, string $file, int $line) use ($reporting): bool {

            if (error_reporting() !== $reporting) {
                return false;
            }

            throw new \ErrorException($message, 0, $severity, $file, $line);
        }, E_WARNING | E_NOTICE | E_USER_WARNING | E_USER_NOTICE);
    }

    /**
     * Put the error handler back.
     *
     * @return void
     */
    #[After]
    protected function stopTreatingWarningsAsErrors(): void
    {
        restore_error_handler();
    }
}
