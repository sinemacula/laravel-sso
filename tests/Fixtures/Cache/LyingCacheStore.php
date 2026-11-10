<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Cache;

use Illuminate\Cache\ArrayLock;
use Illuminate\Cache\ArrayStore;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Store;

/**
 * A cache that answers falsely (SSO-11.6): it reports every write as made and
 * forgets it, or answers every read with the value given, whatever was asked,
 * and its locks are either always free or never, so a test can lie in whichever
 * direction would hurt: a mutex held for ever, or one that excludes nobody.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LyingCacheStore implements LockProvider, Store
{
    /** @var int How many calls have reached the store. */
    public int $calls = 0;

    /**
     * Constructor.
     *
     * @param  mixed  $answer
     * @param  bool  $locksFree
     */
    public function __construct(

        /** What every read answers: `null` is a cache that loses everything. */
        private mixed $answer = null,

        /** Whether every lock is granted: `false` is a mutex held for ever. */
        private bool $locksFree = true,
    ) {}

    /**
     * Answer the lie.
     *
     * @param  mixed  $key
     * @return mixed
     */
    #[\Override]
    public function get(mixed $key): mixed
    {
        $this->calls++;

        return $this->answer;
    }

    /**
     * Answer the lie for each key.
     *
     * @param  array<array-key, mixed>  $keys
     * @return array<string, mixed>
     */
    #[\Override]
    public function many(array $keys): array
    {
        $this->calls++;

        return array_fill_keys(array_filter($keys, is_string(...)), $this->answer);
    }

    /**
     * Report the write as made, and forget it.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @param  mixed  $seconds
     * @return bool
     */
    #[\Override]
    public function put(mixed $key, mixed $value, mixed $seconds): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate
    {
        $this->calls++;

        return true;
    }

    /**
     * Report the writes as made, and forget them.
     *
     * @param  array<array-key, mixed>  $values
     * @param  mixed  $seconds
     * @return bool
     */
    #[\Override]
    public function putMany(array $values, mixed $seconds): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate
    {
        $this->calls++;

        return true;
    }

    /**
     * Report a count of one, whatever it was.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @return int
     */
    #[\Override]
    public function increment(mixed $key, mixed $value = 1): int
    {
        $this->calls++;

        return 1;
    }

    /**
     * Report a count of nothing, whatever it was.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @return int
     */
    #[\Override]
    public function decrement(mixed $key, mixed $value = 1): int
    {
        $this->calls++;

        return 0;
    }

    /**
     * Report the write as made, and forget it.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @return bool
     */
    #[\Override]
    public function forever(mixed $key, mixed $value): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate
    {
        $this->calls++;

        return true;
    }

    /**
     * Report the change of expiry as made. The contract of every supported
     * Laravel but the oldest names it.
     *
     * @param  mixed  $key
     * @param  mixed  $seconds
     * @return bool
     *
     * @phpstan-ignore method.missingOverride
     */
    public function touch(mixed $key, mixed $seconds): bool // phpcs:ignore SineMacula.NamingConventions.BooleanMethodName.NotPredicate
    {
        $this->calls++;

        return true;
    }

    /**
     * Report the removal as made.
     *
     * @param  mixed  $key
     * @return bool
     */
    #[\Override]
    public function forget(mixed $key): bool
    {
        $this->calls++;

        return true;
    }

    /**
     * Report the flush as made.
     *
     * @return bool
     */
    #[\Override]
    public function flush(): bool
    {
        $this->calls++;

        return true;
    }

    /**
     * The prefix: none.
     *
     * @return string
     */
    #[\Override]
    public function getPrefix(): string
    {
        return '';
    }

    /**
     * A lock that is always free, a new store's each time, or never free, held
     * already by someone else.
     *
     * @param  string  $name
     * @param  int  $seconds
     * @param  ?string  $owner
     * @return \Illuminate\Contracts\Cache\Lock
     */
    #[\Override]
    public function lock(mixed $name, mixed $seconds = 0, mixed $owner = null): Lock
    {
        $this->calls++;

        $store = new ArrayStore;

        if (!$this->locksFree) {
            $store->lock($name, $seconds, 'someone-else')->get();
        }

        return new ArrayLock($store, $name, $seconds, $owner);
    }

    /**
     * The lock of the owner given.
     *
     * @param  string  $name
     * @param  string  $owner
     * @return \Illuminate\Contracts\Cache\Lock
     */
    #[\Override]
    public function restoreLock(mixed $name, mixed $owner): Lock
    {
        return $this->lock($name, 0, $owner);
    }
}
