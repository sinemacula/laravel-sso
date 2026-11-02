<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Before;

/**
 * Makes any PHP warning or notice the code under test raises an error of the
 * test, for a test that does not boot the framework: PHPUnit only records one,
 * so reading a member that is not there would otherwise pass unnoticed. Hostile
 * input must be refused, never read past with a warning.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait TreatsWarningsAsErrors
{
    /**
     * Throw on a warning or notice for the rest of the test; one silenced with
     * `@` stays silent, which shows as a reporting level other than the test's
     * own (PHPUnit lowers that level while a test runs, so it cannot be read as
     * the levels that are reported).
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
