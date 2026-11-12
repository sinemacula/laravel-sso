<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\SingleUse;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\UniqueConstraintViolationException;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Database\RetriedTransaction;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * The default single-use store: the table's unique index, never a read, decides
 * whether a key is held.
 *
 * Each statement runs in its own transaction, a savepoint inside the caller's,
 * so a refused insert never aborts the caller's transaction on PostgreSQL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DatabaseSingleUseStore implements SingleUseStore
{
    /** @var string A namespace of 1 to 64 safe characters. */
    private const string NAMESPACE_PATTERN = '/^[a-z0-9_.:\-]{1,64}$/D';

    /** @var int How many times a statement rolled back as a deadlock is tried in all. */
    private const int ATTEMPTS = 3;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock expiries are checked against. */
        private Clock $clock,
    ) {}

    /**
     * Record the key until the expiry, rounded up to the second, unless it is
     * already held.
     *
     * @param  string  $namespace
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $until
     * @return \SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    #[\Override]
    public function record(string $namespace, #[\SensitiveParameter] string $key, CarbonImmutable $until): SingleUseOutcome
    {
        $now = $this->clock->now();

        $this->assertValid($namespace, $key, $until, $now);

        $model      = new SingleUseKey;
        $connection = $model->getConnection();
        $table      = $model->getTable();
        $digest     = hash('sha256', $key);

        $row = [
            'namespace'  => $namespace,
            'key_digest' => $digest,
            'expires_at' => UtcDateTime::format($model, $until->ceilSecond()),
        ];

        if ($this->store($connection, $table, $row)) {
            return SingleUseOutcome::RECORDED;
        }

        // Insert again whatever the delete removed: only the index can say
        // whether a live holder is left.
        $this->deleteExpired($connection, $table, $namespace, $digest, UtcDateTime::format($model, $now));

        return $this->store($connection, $table, $row) ? SingleUseOutcome::RECORDED : SingleUseOutcome::SEEN;
    }

    /**
     * Refuse a malformed namespace, an empty key or a past expiry.
     *
     * @param  string  $namespace
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $until
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertValid(string $namespace, #[\SensitiveParameter] string $key, CarbonImmutable $until, CarbonImmutable $now): void
    {
        if (preg_match(self::NAMESPACE_PATTERN, $namespace) !== 1) {
            throw new \InvalidArgumentException('A single-use namespace must be 1 to 64 characters of lower case letters, digits, `_`, `.`, `:` and `-`.');
        }

        if ($key === '') {
            throw new \InvalidArgumentException('A single-use key must not be empty.');
        }

        if ($until <= $now) {
            throw new \InvalidArgumentException('A single-use key must be recorded until a moment after now.');
        }
    }

    /**
     * Insert the row, returning `false` when the unique index refuses it.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  array{namespace: string, key_digest: string, expires_at: string}  $row
     * @return bool
     *
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    private function store(Connection $connection, string $table, array $row): bool
    {
        $insert = static fn (Connection $connection): bool => $connection->table($table)->insert($row);

        try {
            RetriedTransaction::run($connection, $insert, self::ATTEMPTS);
        } catch (UniqueConstraintViolationException) {
            return false;
        }

        return true;
    }

    /**
     * Delete the key's row if its expiry has passed.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $table
     * @param  string  $namespace
     * @param  string  $digest
     * @param  string  $now
     * @return void
     *
     * @throws \Throwable
     */
    private function deleteExpired(Connection $connection, string $table, string $namespace, string $digest, string $now): void
    {
        $delete = static fn (Connection $connection): int => $connection->table($table)
            ->where('namespace', $namespace)
            ->where('key_digest', $digest)
            ->where('expires_at', '<=', $now)
            ->delete();

        RetriedTransaction::run($connection, $delete, self::ATTEMPTS);
    }
}
