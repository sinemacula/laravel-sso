<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Cache\CacheManager;
use Illuminate\Contracts\Cache\Store;
use Tests\Fixtures\Cache\BrokenCacheStore;
use Tests\Fixtures\Cache\LyingCacheStore;

/**
 * Makes the application's default cache one that is down or lies (SSO-11.6), so
 * a test can show nothing depended on it. The store is registered under its own
 * driver and made the default before anything resolves it; every store a test
 * makes is left as it was afterwards only by the application being rebuilt, so
 * a test uses it for its own lifetime.
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
     * Make the default cache one that loses every write and answers every read
     * with the value given; its locks are always free or never.
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

        // Not static: Laravel 12 binds a creator to the manager, which a static
        // closure refuses.
        $manager->extend('sso_unreliable', fn (mixed $app): mixed => $manager->repository($store));

        config()->set('cache.stores.sso_unreliable', ['driver' => 'sso_unreliable']);
        config()->set('cache.default', 'sso_unreliable');

        $manager->forgetDriver('sso_unreliable');
    }
}
