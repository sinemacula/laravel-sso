<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Application;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Who the example application's request is authenticated as, in the package's
 * terms (SSO-12.5): the identity, the acting identity a management change
 * records, the tenant the caller is active in and the session it is on.
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
     * The identity the request is authenticated as.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public static function identity(Request $request): IdentityReference
    {
        $user = self::user($request);

        return new IdentityReference(User::TYPE, $user->id);
    }

    /**
     * The acting identity a management change records.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Sso\Administration\ActingIdentity
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public static function actor(Request $request): ActingIdentity
    {
        $user = self::user($request);

        return new ActingIdentity(User::TYPE, $user->id);
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
