<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Cache\CacheManager;
use Illuminate\Contracts\Cache\Store;
use Tests\Fixtures\Cache\BrokenCacheStore;
use Tests\Fixtures\Cache\LyingCacheStore;

/**
 * Makes the default cache one that is down or lies, for the test's lifetime.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesUnreliableCache
{
    /**
     * Make the default cache one whose every call throws.
     *
     * @return \Tests\Fixtures\Cache\BrokenCacheStore
     */
    protected function breakTheCache(): BrokenCacheStore
    {
        $store = new BrokenCacheStore;

        $this->useCacheStore($store);

        return $store;
    }

    /**
     * Make the default cache lose every write and answer every read with the
     * value given; its locks are always free or never.
     *
     * @param  mixed  $answer
     * @param  bool  $locksFree
     * @return \Tests\Fixtures\Cache\LyingCacheStore
     */
    protected function makeTheCacheLie(mixed $answer = null, bool $locksFree = true): LyingCacheStore
    {
        $store = new LyingCacheStore($answer, $locksFree);

        $this->useCacheStore($store);

        return $store;
    }

    /**
     * Make the store the application's default cache.
     *
     * @param  \Illuminate\Contracts\Cache\Store  $store
     * @return void
     */
    private function useCacheStore(Store $store): void
    {
        /** @var \Illuminate\Cache\CacheManager $manager */
        $manager = app(CacheManager::class);

        // Not static: Laravel 12 binds a creator to the manager.
        $manager->extend('sso_unreliable', fn (mixed $app): mixed => $manager->repository($store));

        config()->set('cache.stores.sso_unreliable', ['driver' => 'sso_unreliable']);
        config()->set('cache.default', 'sso_unreliable');

        $manager->forgetDriver('sso_unreliable');
    }
}
