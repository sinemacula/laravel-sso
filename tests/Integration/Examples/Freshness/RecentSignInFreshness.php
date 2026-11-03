<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Freshness;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;

/**
 * The example application's freshness contract (SSO-2.12): the caller of the
 * request being served is fresh for an operation when they authenticated no
 * more than its maximum age ago, read from the Unix timestamp the application's
 * sign-in stores in the session or, on a request with no session, the
 * `auth_time` of the verified token its middleware puts on the request. It
 * judges the age by the package's clock, so a test can move it, and holds
 * nothing of one request for the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecentSignInFreshness implements Freshness
{
    // @snippet-start recent-sign-in-freshness
    /**
     * Take the container and the package's clock.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The container the request being served is resolved from. */
        private Container $container,

        /** The package's clock, which a test can move. */
        private Clock $clock,
    ) {}

    /**
     * Whether the caller authenticated within the maximum age.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds): FreshnessOutcome
    {
        // Every operation is judged alike: a stricter policy would match on
        // the operation's stable name, $operation->value
        unset($operation);

        // The request being served, resolved on each call and never held
        $request = $this->container->make(Request::class);

        if ($request->user() === null) {
            return FreshnessOutcome::STALE;
        }

        $authenticatedAt = $request->hasSession()
            ? $request->session()->get('auth.authenticated_at')
            : $request->attributes->get('auth_time');

        if (!is_int($authenticatedAt)) {
            return FreshnessOutcome::STALE;
        }

        $age = $this->clock->now()->getTimestamp() - $authenticatedAt;

        return $age >= 0 && $age <= $maxAgeSeconds ? FreshnessOutcome::FRESH : FreshnessOutcome::STALE;
    }
    // @snippet-end recent-sign-in-freshness
}
