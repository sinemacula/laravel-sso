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
 * The default single-use store (SSO-11.5): records a key once in its namespace
 * by inserting its digest under the unique index of the single-use table, on
 * the storage connection.
 *
 * The index answers, never a read: an insert that goes in is `recorded`. After
 * one the index refuses, the row it collided with is deleted if it has expired,
 * and the insert is tried once more, whatever the delete removed: a prune or
 * another record may have just deleted that row, so only the index can say
 * whether a holder is left. `seen` therefore always names a live row. Each
 * statement runs in a transaction of its own, which Laravel makes a savepoint
 * when the caller already has one open, so a refused insert never aborts the
 * caller's transaction (PostgreSQL would refuse every statement after it), and
 * a lost connection is thrown rather than the insert retried. Every statement
 * is a write, so it runs on the write connection (SSO-11.3).
 *
 * A statement the database rolls back as a deadlock or a serialisation failure
 * wrote nothing, so it is tried again, at most three times in all, when the
 * store opened the transaction itself (two racing inserts of a key whose
 * expired row was just deleted can deadlock on MySQL). Inside the caller's
 * transaction it is thrown, since the database has rolled that transaction back
 * too.
 *
 * Every other database error propagates unchanged, and the flow is refused as a
 * server error (SSO-11.4). A record made inside the caller's transaction is
 * undone with it.
 *
 * The store holds nothing between calls, and is bound scoped (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DatabaseSingleUseStore implements SingleUseStore
{
    /** @var string A namespace: 1 to 64 lower case letters, digits, `_`, `.`, `:` and `-`, with nothing after them, not even a newline. */
    private const string NAMESPACE_PATTERN = '/^[a-z0-9_.:\-]{1,64}$/D';

    /** @var int Times a statement is tried when the database rolls it back as a deadlock or serialisation failure, in a transaction the store opened. */
    private const int ATTEMPTS = 3;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock an expiry is checked and compared against */
        private Clock $clock,
    ) {}

    /**
     * Record the key in the namespace until the expiry, unless it is held
     * there: `recorded` when it was not, `seen` when it was.
     *
     * The expiry is kept to the whole second, rounded up, so a key is never
     * released before it; a key is released from the second its expiry names.
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
            'expires_at' => $this->format($model, $until->ceilSecond()),
        ];

        if ($this->store($connection, $table, $row)) {
            return SingleUseOutcome::RECORDED;
        }

        $this->deleteExpired($connection, $table, $namespace, $digest, $this->format($model, $now));

        return $this->store($connection, $table, $row) ? SingleUseOutcome::RECORDED : SingleUseOutcome::SEEN;
    }

    /**
     * Refuse a malformed namespace, an empty key or an expiry that is not after
     * now, before any statement runs. No message names the key.
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
     * Insert the row in a transaction of its own (a savepoint inside the
     * caller's), unless the unique index refuses it. Returns whether it went
     * in; any other error propagates.
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
     * Delete the key's row if its expiry has passed, in a transaction of its
     * own (a savepoint inside the caller's). A row still held is never touched.
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

    /**
     * Format an instant as the storage connection stores times, in UTC, to the
     * whole second, so no daylight-saving change can make a held key read as
     * expired (see `Models\Casts\UtcDateTime`).
     *
     * @param  \SineMacula\Laravel\Sso\Models\SingleUseKey  $model
     * @param  \Carbon\CarbonImmutable  $instant
     * @return string
     */
    private function format(SingleUseKey $model, CarbonImmutable $instant): string
    {
        return UtcDateTime::format($model, $instant);
    }
}
