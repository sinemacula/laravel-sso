<?php

declare(strict_types = 1);

namespace Tests\Integration\Support;

use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\View\Middleware\ShareErrorsFromSession;
use Orchestra\Testbench\Http\Kernel;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Linker;
use Tests\Fixtures\Links\FixedLinker;
use Tests\StandaloneTestCase;

/**
 * Shows the standalone base stands alone (FEATURES "No dependency on a
 * sibling"): no sibling and no session middleware in the kernel or the router,
 * every seam on its default, and a test that replaced one, added a session
 * middleware or found a sibling installed is told so.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class StandaloneTestCaseTest extends StandaloneTestCase
{
    /**
     * Nothing has crept in, and every seam is on the default the package binds.
     *
     * @return void
     */
    public function testStandsAloneOnEveryDefault(): void
    {
        $this->assertStandalone();
        $this->assertDefaultBindings();
    }

    /**
     * A seam replaced fails the assertion, so a binding cannot replace a
     * default by accident.
     *
     * @return void
     */
    public function testAReplacedSeamIsNoticed(): void
    {
        $this->app?->instance(Linker::class, new FixedLinker(null));

        try {
            $this->assertDefaultBindings();
        } catch (AssertionFailedError $failure) { // @phpstan-ignore catch.neverThrown (an assertion throws it)
            self::assertStringContainsString('Linker is not bound to its default', $failure->getMessage());

            return;
        }

        self::fail('A replaced seam went unnoticed.');
    }

    /**
     * Taking the groups away reaches the router too, whose copy of them the
     * kernel's own setter leaves behind: no group anywhere names a session.
     *
     * @return void
     */
    public function testNoMiddlewareGroupAnywhereNamesASession(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = app('router');

        self::assertSame([], array_merge([], ...array_values($router->getMiddlewareGroups())));
    }

    /**
     * Rows of `[how a session middleware crept in, its name]`: on the kernel's
     * stack, in a group of the kernel, in a group of the router alone, and the
     * forgery check that goes with a session.
     *
     * @return iterable<string, array{0: \Closure(\Orchestra\Testbench\Http\Kernel, \Illuminate\Routing\Router): mixed, 1: class-string}>
     */
    public static function provideSessionMiddleware(): iterable
    {
        $inRouter = static fn (string $middleware): \Closure => static fn (Kernel $kernel, Router $router): mixed => $router->middlewareGroup('web', [$middleware]);

        yield 'on the global stack' => [static fn (Kernel $kernel): mixed => $kernel->pushMiddleware(StartSession::class), StartSession::class];
        yield 'in a group of the kernel' => [static fn (Kernel $kernel): mixed => $kernel->setMiddlewareGroups(['web' => [StartSession::class]]), StartSession::class];
        yield 'in a group of the router' => [$inRouter(ShareErrorsFromSession::class), ShareErrorsFromSession::class];
        yield 'the forgery check' => [$inRouter(PreventRequestForgery::class), PreventRequestForgery::class];
    }

    /**
     * Whichever way a session middleware crept in, the assertion names it.
     *
     * @param  \Closure(\Orchestra\Testbench\Http\Kernel, \Illuminate\Routing\Router): mixed  $add
     * @param  class-string  $middleware
     * @return void
     */
    #[DataProvider('provideSessionMiddleware')]
    public function testASessionMiddlewareIsNoticed(\Closure $add, string $middleware): void
    {
        /** @var \Orchestra\Testbench\Http\Kernel $kernel */
        $kernel = app(HttpKernel::class);

        /** @var \Illuminate\Routing\Router $router */
        $router = app('router');

        $add($kernel, $router);

        try {
            $this->assertStandalone();
        } catch (AssertionFailedError $failure) { // @phpstan-ignore catch.neverThrown (an assertion throws it)
            self::assertSame("The application names the session middleware {$middleware}.", $failure->getMessage());

            return;
        }

        self::fail('A session middleware went unnoticed.');
    }

    /**
     * A sibling is any other package of the family, and this package none.
     *
     * @return void
     */
    public function testASiblingIsNoticedAndThisPackageIsNot(): void
    {
        self::assertSame(
            ['sinemacula/laravel-authentication', 'sinemacula/laravel-iam'],
            self::siblingsAmong(['sinemacula/laravel-sso', 'sinemacula/laravel-authentication', 'laravel/framework', 'sinemacula/laravel-iam', 'sinemacula/other']),
        );
    }
}
