<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Queue;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

/**
 * A job that records its run, resolves a scoped binding of the test's where it
 * has one, and throws when told to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordsItsRun implements ShouldQueue
{
    use Queueable;

    /** @var string What a test binds as scoped, for each job to resolve. */
    public const string SCOPED = 'sso.test.scoped';

    /** @var list<string> Every run so far, in order. */
    public static array $runs = [];

    /**
     * Constructor.
     *
     * @param  string  $label
     */
    public function __construct(

        /** What the run is recorded as. */
        public string $label,
    ) {}

    /**
     * Record the run, resolve the scoped binding, and throw when told to.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    public function handle(): void
    {
        self::$runs[] = $this->label;

        if (app()->bound(self::SCOPED)) {
            app(self::SCOPED);
        }

        if ($this->label === 'throw') {
            throw new \RuntimeException('The job failed.');
        }
    }
}
