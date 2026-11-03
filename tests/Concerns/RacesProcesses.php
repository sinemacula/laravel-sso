<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;

/**
 * Races forked processes on a shared database server, each with its own
 * connection, and establishes the order a test claims with explicit signals,
 * never with timing (BL-73 and the races of every other item).
 *
 * `setUpRace()` skips where processes cannot share a database, on SQLite or
 * without `pcntl`, and makes a directory for the signals and the reports;
 * `tearDownRace()` removes it. Anything expensive that fixtures cache per
 * process (a certificate, a key) is made before `race()`, or each child makes
 * its own.
 *
 * `race()` forks one process per racer. Each opens its own connection, runs
 * `$before` if given (an open transaction's reads, say), signals that it is
 * ready and waits for the rest, so all start together, then runs its racer and
 * reports. A racer that must find a lock held waits for an explicit signal from
 * the holder through `awaitSignal()`; the holder raises it with `signal()` once
 * it holds the lock, and not merely once it has started. Every wait fails
 * loudly at `RACE_DEADLINE_SECONDS`.
 *
 * With `inTransaction`, each racer runs inside a transaction of its own on the
 * connection named, opened before the start, with `$before` run in it, so its
 * snapshot predates every change, and committed after its work: a re-read that
 * decides a write must then be a locking one.
 *
 * A report carries the racer's `result`, JSON-encodable, and `error`: the
 * exception's class and message, or `RACE_SERIALIZATION_FAILURE` for a
 * PostgreSQL serialisation failure (SQLSTATE 40001, possibly wrapped in a
 * `DeadlockException`: the chain is walked), which is an accepted safe outcome
 * on PostgreSQL only, and so reported as a failure anywhere else.
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
     * Skip where processes cannot share the database, and make the directory
     * the processes use.
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
     * Race the racers and answer each one's report, in the order given. Each
     * racer is given its index.
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
     * Assert no racer failed but for a serialisation failure, on PostgreSQL
     * alone where it is accepted, and answer the results of those that
     * finished.
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
     * In a forked process: open a connection of its own, signal it is ready,
     * wait for the rest, run the racer, report, and end without running the
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
