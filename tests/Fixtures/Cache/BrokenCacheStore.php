<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Cache;

use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Store;

/**
 * A cache that is down: every read, write and lock throws, as a Redis or
 * Memcached client does when its server has gone. It counts every call, so a
 * test can show that something depended on the cache, or that nothing did.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BrokenCacheStore implements LockProvider, Store
{
    /** @var int How many calls have reached the store. */
    public int $calls = 0;

    /**
     * Fail a read.
     *
     * @param  mixed  $key
     * @return never
     */
    #[\Override]
    public function get(mixed $key): never
    {
        $this->fail();
    }

    /**
     * Fail a read of many.
     *
     * @param  array<array-key, mixed>  $keys
     * @return never
     */
    #[\Override]
    public function many(array $keys): never
    {
        $this->fail();
    }

    /**
     * Fail a write.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @param  mixed  $seconds
     * @return never
     */
    #[\Override]
    public function put(mixed $key, mixed $value, mixed $seconds): never
    {
        $this->fail();
    }

    /**
     * Fail a write of many.
     *
     * @param  array<array-key, mixed>  $values
     * @param  mixed  $seconds
     * @return never
     */
    #[\Override]
    public function putMany(array $values, mixed $seconds): never
    {
        $this->fail();
    }

    /**
     * Fail an increment.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @return never
     */
    #[\Override]
    public function increment(mixed $key, mixed $value = 1): never
    {
        $this->fail();
    }

    /**
     * Fail a decrement.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @return never
     */
    #[\Override]
    public function decrement(mixed $key, mixed $value = 1): never
    {
        $this->fail();
    }

    /**
     * Fail a write with no expiry.
     *
     * @param  mixed  $key
     * @param  mixed  $value
     * @return never
     */
    #[\Override]
    public function forever(mixed $key, mixed $value): never
    {
        $this->fail();
    }

    /**
     * Fail a change of expiry. The contract of every supported Laravel but the
     * oldest names it.
     *
     * @param  mixed  $key
     * @param  mixed  $seconds
     * @return never
     *
     * @phpstan-ignore method.missingOverride
     */
    public function touch(mixed $key, mixed $seconds): never
    {
        $this->fail();
    }

    /**
     * Fail a removal.
     *
     * @param  mixed  $key
     * @return never
     */
    #[\Override]
    public function forget(mixed $key): never
    {
        $this->fail();
    }

    /**
     * Fail a flush.
     *
     * @return never
     */
    #[\Override]
    public function flush(): never
    {
        $this->fail();
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
     * Fail taking a lock.
     *
     * @param  mixed  $name
     * @param  mixed  $seconds
     * @param  mixed  $owner
     * @return \Illuminate\Contracts\Cache\Lock
     */
    #[\Override]
    public function lock(mixed $name, mixed $seconds = 0, mixed $owner = null): Lock
    {
        $this->fail();
    }

    /**
     * Fail restoring a lock.
     *
     * @param  mixed  $name
     * @param  mixed  $owner
     * @return \Illuminate\Contracts\Cache\Lock
     */
    #[\Override]
    public function restoreLock(mixed $name, mixed $owner): Lock
    {
        $this->fail();
    }

    /**
     * Count the call, and fail as a client whose server has gone does.
     *
     * @return never
     *
     * @throws \RuntimeException
     */
    private function fail(): never
    {
        $this->calls++;

        throw new \RuntimeException('The cache is down.');
    }
}
