<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;

/**
 * Races forked processes on a shared database server, ordered by signals. A
 * holder signals once it holds the lock, never merely once it has started.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RacesProcesses
{
    /** @var string What a racer that failed to serialise reports as its error. */
    protected const string RACE_SERIALIZATION_FAILURE = 'serialization_failure';

    /** @var float How long, in seconds, a process waits for another before it fails. */
    protected const float RACE_DEADLINE_SECONDS = 30.0;

    /** @var ?string The directory the processes signal and report in. */
    private ?string $raceDirectory = null;

    /**
     * Skip where processes cannot share the database, and make the directory.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    protected function setUpRace(): void
    {
        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->raceDirectory = sys_get_temp_dir() . '/sso-race-' . bin2hex(random_bytes(8));

        mkdir($this->raceDirectory);
    }

    /**
     * Remove the directory the processes used.
     *
     * @return void
     */
    protected function tearDownRace(): void
    {
        if ($this->raceDirectory === null || !is_dir($this->raceDirectory)) {
            return;
        }

        foreach (glob($this->raceDirectory . '/*') ?: [] as $file) {
            unlink($file);
        }

        rmdir($this->raceDirectory);

        $this->raceDirectory = null;
    }

    /**
     * Race the racers, started together, and answer their reports in order.
     * `$inTransaction` runs each racer and its `$before` in one transaction.
     *
     * @param  list<\Closure(int): mixed>  $racers
     * @param  ?string  $inTransaction
     * @param  ?\Closure(int): void  $before
     * @return list<array{result: mixed, error: ?string}>
     */
    protected function race(array $racers, ?string $inTransaction = null, ?\Closure $before = null): array
    {
        DB::purge();

        $pids = [];

        foreach ($racers as $index => $racer) {

            $pid = pcntl_fork();

            Assert::assertNotSame(-1, $pid, 'A racer could not be forked.');

            if ($pid === 0) {
                $this->runRacer($index, count($racers), $racer, $inTransaction, $before);
            }

            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }

        DB::purge();

        return array_map(fn (int $index): array => $this->raceReport($index), array_keys($racers));
    }

    /**
     * Raise the named signal, for a process waiting on it.
     *
     * @param  string  $name
     * @return void
     */
    protected function signal(string $name): void
    {
        touch($this->raceDirectory . '/signal-' . $name);
    }

    /**
     * Wait for the named signal, failing loudly at the deadline.
     *
     * @param  string  $name
     * @return void
     *
     * @throws \RuntimeException
     */
    protected function awaitSignal(string $name): void
    {
        $file     = $this->raceDirectory . '/signal-' . $name;
        $deadline = microtime(true) + self::RACE_DEADLINE_SECONDS;

        while (!is_file($file)) {

            if (microtime(true) > $deadline) {
                throw new \RuntimeException("Timed out waiting for the signal `{$name}`.");
            }

            usleep(1000);
        }
    }

    /**
     * Assert no racer failed, bar a serialisation failure on PostgreSQL, and
     * answer the results of those that finished.
     *
     * @param  list<array{result: mixed, error: ?string}>  $reports
     * @return list<mixed>
     */
    protected function assertRacersSucceeded(array $reports): array
    {
        $results = [];

        foreach ($reports as $index => $report) {

            if ($report['error'] === self::RACE_SERIALIZATION_FAILURE) {
                self::assertSame('pgsql', DB::connection()->getDriverName(), "Racer {$index} failed to serialise outside PostgreSQL.");

                continue;
            }

            self::assertNull($report['error'], "Racer {$index} failed: " . $report['error']);

            $results[] = $report['result'];
        }

        return $results;
    }

    /**
     * Whether the exception, or anything it wraps, is a serialisation failure.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function isSerializationFailure(\Throwable $exception): bool
    {
        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            if ((string) $current->getCode() === '40001') {
                return true;
            }
        }

        return false;
    }

    /**
     * Run the racer in the forked child, report, and die without running the
     * parent's shutdown.
     *
     * @param  int  $index
     * @param  int  $racers
     * @param  \Closure(int): mixed  $racer
     * @param  ?string  $inTransaction
     * @param  ?\Closure(int): void  $before
     * @return never
     */
    private function runRacer(int $index, int $racers, \Closure $racer, ?string $inTransaction, ?\Closure $before): never
    {
        $report = ['result' => null, 'error' => null];

        try {
            DB::purge();
            DB::connection()->getPdo();

            $database = $inTransaction === null ? null : DB::connection($inTransaction);

            $database?->beginTransaction();

            if ($before !== null) {
                $before($index);
            }

            $this->signal("ready-{$index}");

            for ($other = 0; $other < $racers; $other++) {
                $this->awaitSignal("ready-{$other}");
            }

            $report['result'] = $racer($index);

            $database?->commit();
        } catch (\Throwable $exception) {
            $report['error'] = self::isSerializationFailure($exception) ? self::RACE_SERIALIZATION_FAILURE : $exception::class . ': ' . $exception->getMessage();
        }

        file_put_contents("{$this->raceDirectory}/report-{$index}", json_encode($report));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * The racer's report.
     *
     * @param  int  $index
     * @return array{result: mixed, error: ?string}
     */
    private function raceReport(int $index): array
    {
        /** @var ?array{result: mixed, error: ?string} $report */
        $report = json_decode((string) @file_get_contents("{$this->raceDirectory}/report-{$index}"), true);

        return $report ?? ['result' => null, 'error' => "racer {$index} reported nothing"];
    }
}
