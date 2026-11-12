<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Application;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Identities\Caller as SsoCaller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The authenticated caller, tenant and session of a request, each from the
 * application's authentication, never the request body.
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
     * The identity the request is authenticated as, on its session.
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
     * The resolved user, when it is this application's user.
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
