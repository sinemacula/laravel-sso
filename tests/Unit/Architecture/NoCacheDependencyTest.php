<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Concerns\ScansLibraryNames;

/**
 * Holds the package to needing no cache (SSO-11.6): nothing it ships names the
 * cache's classes, its facades or its rate limiter, calls the `cache()` helper
 * or resolves the cache from the container; and only
 * `Operations\OperationsSchedule`, behind an explicit opt-in, names the
 * scheduler's cache mutexes.
 *
 * Names are read as `ScansLibraryNames` reads them, and calls and container
 * keys from the source's tokens, so a comment that mentions the cache is not
 * one that uses it. The scan is a backstop:
 * `Integration\Failures\CacheOutageTest` proves the behaviour.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class NoCacheDependencyTest extends TestCase
{
    use ScansLibraryNames;

    /** @var string The one class that may name a mutex. */
    private const string MUTEX_OWNER = 'src/Operations/OperationsSchedule.php';

    /** @var string A name of the cache: its namespaces, its contracts, its facades and its aliases. */
    private const string CACHE_NAME = '/^\\\?(?:Illuminate\\\(?:Contracts\\\)?Cache\\\|(?:Illuminate\\\Support\\\Facades\\\)?(?:Cache|RateLimiter)$)/';

    /** @var list<string> What a source resolving the cache from the container says. */
    private const array CONTAINER_KEYS = ['cache', 'cache.store', 'cache.psr6'];

    /** @var list<string> The methods that take a mutex in the schedule's cache. */
    private const array MUTEX_METHODS = ['withoutOverlapping', 'onOneServer', 'useCache', 'createMutexNameUsing'];

    /**
     * Rows of `[path]`: every PHP file the package ships.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSources(): iterable
    {
        foreach (array_keys(self::shippedSources()) as $path) {
            yield $path => [$path];
        }
    }

    /**
     * Nothing names a class of the cache.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testNothingNamesTheCache(string $path): void
    {
        self::assertSame([], array_column(self::scannedNames(self::shippedSources()[$path], self::CACHE_NAME), 0), "{$path} names the cache.");
    }

    /**
     * Nothing calls the `cache()` helper or resolves the cache from the
     * container.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testNothingResolvesTheCache(string $path): void
    {
        self::assertSame([], self::cacheUses(self::shippedSources()[$path]), "{$path} resolves the cache.");
    }

    /**
     * A scheduler's cache mutex is named in the one class that opts in to it.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testOnlyTheScheduleNamesAMutex(string $path): void
    {
        $named = self::mutexCalls(self::shippedSources()[$path]);

        if ($path === self::MUTEX_OWNER) {
            self::assertSame(['withoutOverlapping', 'onOneServer'], $named);

            return;
        }

        self::assertSame([], $named, "{$path} names a scheduler's cache mutex.");
    }

    /**
     * Rows of `[source]`: each way of reaching the cache the scan is to catch.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOffences(): iterable
    {
        yield 'the facade imported' => ['<?php use Illuminate\Support\Facades\Cache;'];
        yield 'the rate limiter imported' => ['<?php use Illuminate\Support\Facades\RateLimiter;'];
        yield 'the facade by its root alias' => ['<?php \Cache::get("a");'];
        yield 'the contract imported' => ['<?php use Illuminate\Contracts\Cache\Repository;'];
        yield 'the manager named' => ['<?php new \Illuminate\Cache\CacheManager($app);'];
    }

    /**
     * The name scan catches each way of naming the cache.
     *
     * @param  string  $source
     * @return void
     */
    #[DataProvider('provideOffences')]
    public function testTheNameScanCatchesAnOffence(string $source): void
    {
        self::assertNotSame([], self::scannedNames($source, self::CACHE_NAME));
    }

    /**
     * The use scan catches the helper and the container's keys, and passes over
     * a comment, a method of that name and a header of a similar one.
     *
     * @return void
     */
    public function testTheUseScanTellsAUseFromAMention(): void
    {
        self::assertSame(['cache('], self::cacheUses('<?php cache()->get("a");'));
        self::assertSame(['\'cache\''], self::cacheUses('<?php app(\'cache\');'));
        self::assertSame(['\'cache.store\''], self::cacheUses('<?php $app->make(\'cache.store\');'));
        self::assertSame([], self::cacheUses('<?php /* cache() and \'cache\' */ $this->cache(); Foo::cache(); $a = \'Cache-Control\'; function cache() {}'));
    }

    /**
     * What resolves the cache in the source: a call of the `cache()` helper, or
     * a string that is a key of the cache in the container.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function cacheUses(string $source): array
    {
        $tokens = self::significantTokens($source);
        $found  = [];

        foreach ($tokens as $index => $token) {

            if (!is_array($token)) {
                continue;
            }

            if ($token[0] === T_CONSTANT_ENCAPSED_STRING && in_array(substr($token[1], 1, -1), self::CONTAINER_KEYS, true)) {
                $found[] = $token[1];
            }

            if (!self::isHelperCall($token, $tokens[$index - 1] ?? null, $tokens[$index + 1] ?? null)) {
                continue;
            }

            $found[] = 'cache(';
        }

        return $found;
    }

    /**
     * Whether the token is a call of the `cache()` helper, and not a method or
     * a function of that name being declared.
     *
     * @param  array{0: int, 1: string, 2: int}  $token
     * @param  array{0: int, 1: string, 2: int}|string|null  $previous
     * @param  array{0: int, 1: string, 2: int}|string|null  $next
     * @return bool
     */
    private static function isHelperCall(array $token, array|string|null $previous, array|string|null $next): bool
    {
        if ($token[0] !== T_STRING || strtolower($token[1]) !== 'cache' || $next !== '(') {
            return false;
        }

        return !is_array($previous) || !in_array($previous[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true);
    }

    /**
     * The mutex methods the source calls, in order.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function mutexCalls(string $source): array
    {
        $named = [];

        foreach (self::significantTokens($source) as $token) {

            if (!is_array($token) || $token[0] !== T_STRING || !in_array($token[1], self::MUTEX_METHODS, true)) {
                continue;
            }

            $named[] = $token[1];
        }

        return $named;
    }

    /**
     * The source's tokens, without whitespace and comments.
     *
     * @param  string  $source
     * @return list<array{0: int, 1: string, 2: int}|string>
     */
    private static function significantTokens(string $source): array
    {
        return array_values(array_filter(
            token_get_all($source),
            static fn (array|string $token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));
    }
}
