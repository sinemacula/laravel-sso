<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use Tests\Concerns\ScansLibraryNames;

/**
 * Holds the package to what stays the application's (SSO-1.2, FEATURES "Useful
 * alone"): who may administer is the application's authorisation, so nothing
 * the package ships names Laravel's gate or its authorisation contracts, or
 * asks `can()`, `cannot()` or `authorize()`; and the package never signs a
 * person in, keeps a session or issues a token, so nothing names Laravel's
 * authentication, its guards, its session or its cookies, calls the `auth()`,
 * `session()` or `cookie()` helpers (by their plain or fully qualified name),
 * reaches them through a request or the container with `session()`, `cookie()`,
 * `guard()` or `user()`, or asks a guard to `login()`, `loginUsingId()`,
 * `logout()` or `createToken()`. A redemption answers a verified result; what
 * the application makes of it is its own.
 *
 * Names are read as `ScansLibraryNames` reads them, and calls from the source's
 * tokens, so a comment that mentions a guard is not one that uses it. The scan
 * is a backstop: `Integration\Standalone\DefaultBindingsFlowsTest` redeems a
 * `sign_in` alone and gets a result, with no session or token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
final class ApplicationBoundaryTest extends TestCase
{
    use ScansLibraryNames;

    /** @var string A name of Laravel's authorisation: the gate's facade (imported or by its root alias) and the access contracts and classes. */
    private const string AUTHORIZATION_NAME = '/^\\\?(?:Illuminate\\\(?:Contracts\\\)?Auth\\\Access\\\|(?:Illuminate\\\Support\\\Facades\\\)?Gate$)/';

    /** @var string A name of Laravel's authentication, sessions or cookies: their facades (imported or by their root aliases), contracts and classes. */
    private const string SESSION_NAME = '/^\\\?(?:Illuminate\\\(?:Contracts\\\)?(?:Auth|Session|Cookie)\\\|(?:Illuminate\\\Support\\\Facades\\\)?(?:Auth|Session|Cookie)$)/';

    /** @var list<string> The methods that check a permission. */
    private const array AUTHORIZATION_METHODS = ['can', 'cannot', 'authorize'];

    /** @var list<string> The methods that sign a person in or out, issue a token, or reach a session, a cookie, a guard or its user. */
    private const array SESSION_METHODS = ['login', 'loginusingid', 'logout', 'createtoken', 'session', 'cookie', 'guard', 'user'];

    /** @var list<string> The helpers that reach the application's authentication, session or cookies. */
    private const array SESSION_HELPERS = ['auth', 'session', 'cookie'];

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
     * Nothing names Laravel's authorisation or asks for a permission.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testNothingChecksAPermission(string $path): void
    {
        $source = self::shippedSources()[$path];

        self::assertSame([], array_column(self::scannedNames($source, self::AUTHORIZATION_NAME), 0), "{$path} names Laravel's authorisation.");
        self::assertSame([], self::calls($source, self::AUTHORIZATION_METHODS, []), "{$path} checks a permission.");
    }

    /**
     * Nothing names Laravel's authentication, sessions or cookies, signs a
     * person in or out, or issues a token.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testNothingSignsInOrKeepsASession(string $path): void
    {
        $source = self::shippedSources()[$path];

        self::assertSame([], array_column(self::scannedNames($source, self::SESSION_NAME), 0), "{$path} names Laravel's authentication or session.");
        self::assertSame([], self::calls($source, self::SESSION_METHODS, self::SESSION_HELPERS), "{$path} signs in, keeps a session or issues a token.");
    }

    /**
     * The scans catch each facade, contract and helper, a permission check and
     * a sign-in, and pass over a comment, a declared function, a method of the
     * package's own and a name that only starts like Laravel's.
     *
     * @return void
     */
    public function testTheScansCatchEachWayOfReachingTheApplication(): void
    {
        $source = <<<'PHP'
            <?php
            use Illuminate\Support\Facades\Gate;
            use Illuminate\Contracts\Auth\Access\Gate as Access;
            use Illuminate\Contracts\Auth\StatefulGuard;
            use Illuminate\Support\Facades\Session;
            \Auth::user();
            $user->can('manage');
            Gate::authorize('manage');
            auth()->login($user);
            $guard->loginUsingId(1);
            session()->put('a', 'b');
            $user->createToken('api');
            $request->session()->put('a', 'b');
            \cookie('a');
            app('auth')->guard()->user();
            \Vendor\session();
            // $user->can() in a comment
            function session(): void {}
            $policy->allows($application);
            $authority = new AuthorizationRequest;
            PHP;

        $authorization = ['Illuminate\Support\Facades\Gate', 'Illuminate\Contracts\Auth\Access\Gate'];
        $sessions      = ['Illuminate\Contracts\Auth\Access\Gate', 'Illuminate\Contracts\Auth\StatefulGuard', 'Illuminate\Support\Facades\Session', '\Auth'];

        self::assertSame($authorization, array_column(self::scannedNames($source, self::AUTHORIZATION_NAME), 0));
        self::assertSame($sessions, array_column(self::scannedNames($source, self::SESSION_NAME), 0));
        self::assertSame(['can', 'authorize'], self::calls($source, self::AUTHORIZATION_METHODS, []));
        self::assertSame(
            ['user', 'auth', 'login', 'loginusingid', 'session', 'createtoken', 'session', 'cookie', 'guard', 'user'],
            self::calls($source, self::SESSION_METHODS, self::SESSION_HELPERS),
        );
    }

    /**
     * The methods and helpers of the lists the source calls, in order, by their
     * lower-case name: a method on an object or a class, and a helper called
     * alone, never a function being declared.
     *
     * @param  string  $source
     * @param  list<string>  $methods
     * @param  list<string>  $helpers
     * @return list<string>
     */
    private static function calls(string $source, array $methods, array $helpers): array
    {
        $tokens = array_values(array_filter(
            token_get_all($source),
            static fn ($token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));
        $found = [];

        foreach ($tokens as $index => $token) {

            $name = self::calledName($token, $tokens[$index + 1] ?? null);
            $kind = is_array($tokens[$index - 1] ?? null) ? $tokens[$index - 1][0] : null;

            if ($name === null || !self::isListed($name, $kind, $methods, $helpers)) {
                continue;
            }

            $found[] = $name;
        }

        return $found;
    }

    /**
     * The lower-case name the token calls, or `null` when it is no name
     * followed by an opening parenthesis: a plain name, or a fully qualified
     * one in the global namespace, without its leading backslash.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @param  array{0: int, 1: string, 2: int}|string|null  $next
     * @return ?string
     */
    private static function calledName(array|string $token, array|string|null $next): ?string
    {
        if (!is_array($token) || $next !== '(') {
            return null;
        }

        $global = $token[0] === T_NAME_FULLY_QUALIFIED && substr_count($token[1], '\\') === 1;

        return $token[0] === T_STRING || $global ? strtolower(ltrim($token[1], '\\')) : null;
    }

    /**
     * Whether the name called after a token of the kind is one of the lists': a
     * method on an object or a class, or a helper called alone and not being
     * declared.
     *
     * @param  string  $name
     * @param  ?int  $kind
     * @param  list<string>  $methods
     * @param  list<string>  $helpers
     * @return bool
     */
    private static function isListed(string $name, ?int $kind, array $methods, array $helpers): bool
    {
        if (in_array($kind, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true)) {
            return in_array($name, $methods, true);
        }

        return $kind !== T_FUNCTION && in_array($name, $helpers, true);
    }
}
