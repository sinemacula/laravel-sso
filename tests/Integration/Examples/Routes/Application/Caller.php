<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Application;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Identities\Caller as SsoCaller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Who the example application's request is authenticated as, in the package's
 * terms (SSO-12.5): the caller (`Identities\Caller`), its identity on the
 * session it authenticated with, which freshness and the link confirmation
 * judge and a management change names as acting; the tenant the caller is
 * active in; and the session it is on.
 *
 * Each comes from the application's own authentication, never from the request
 * body: a `link` or `reauthenticate` start, a link redemption and every
 * management call take them from here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Caller
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The caller the request is authenticated as: the identity, on the session
     * it authenticated with.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public static function of(Request $request): SsoCaller
    {
        $user = self::user($request);

        return new SsoCaller(new IdentityReference(User::TYPE, $user->id), $user->sessionId);
    }

    /**
     * The tenant the caller is active in.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public static function tenantId(Request $request): string
    {
        return self::user($request)->tenantId;
    }

    /**
     * The session the request authenticated with.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public static function sessionId(Request $request): string
    {
        return self::user($request)->sessionId;
    }

    /**
     * The authenticated user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Tests\Integration\Examples\Routes\Application\User
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    private static function user(Request $request): User
    {
        return self::authenticated($request->user());
    }

    /**
     * The user the request's authentication resolved, whatever the guard's
     * configured model, or an `AuthenticationException` when it is not this
     * application's user.
     *
     * @param  mixed  $user
     * @return \Tests\Integration\Examples\Routes\Application\User
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    private static function authenticated(mixed $user): User
    {
        if (!$user instanceof User) {
            throw new AuthenticationException;
        }

        return $user;
    }
}
