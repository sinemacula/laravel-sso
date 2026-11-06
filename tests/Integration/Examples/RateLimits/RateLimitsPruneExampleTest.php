<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RateLimits;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use Tests\Integration\Examples\ExampleTestCase;
use Tests\Integration\Examples\ScheduledPrune;

/**
 * The pruning example of `docs/guides/rate-limits.md` (SSO-11.8, SSO-12.5), on
 * the shared example harness: the schedule the guide's `routes/console.php`
 * holds runs `model:prune` hourly, naming the package's counters; run, it
 * deletes the one counter whose window has ended and keeps the live one, which
 * still refuses the attempt over its limit, while the ended one's next attempt
 * starts a window of its own; run again, it deletes nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RateLimit::class)]
#[CoversClass(DatabaseAttemptLimiter::class)]
final class RateLimitsPruneExampleTest extends ExampleTestCase
{
    /** @var string The address whose window ends. */
    private const string OFFICE = '203.0.113.7';

    /** @var string The address whose window is live. */
    private const string ELSEWHERE = '198.51.100.9';

    /**
     * The scheduled `model:prune` deletes only the counter whose window has
     * ended.
     *
     * @return void
     */
    public function testTheScheduledPruneDeletesOnlyEndedWindows(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 1, 'decay_seconds' => 60]);

        $limiter = app(AttemptLimiter::class);
        $start   = static fn (string $ip): bool => $limiter->attempt(AttemptSubject::authorizationRequest(new ClientContext($ip, null)))->isAllowed();

        self::assertTrue($start(self::OFFICE));

        // The office's window ends as the other address's begins
        $this->clock->advance(60);

        self::assertTrue($start(self::ELSEWHERE));

        require __DIR__ . '/console.php';

        $scheduled = ScheduledPrune::scheduled();

        self::assertSame(['expression' => '0 * * * *', 'models' => [RateLimit::class]], $scheduled);
        self::assertSame([RateLimit::class => 1], ScheduledPrune::run($scheduled['models']));

        self::assertFalse($start(self::ELSEWHERE));
        self::assertTrue($start(self::OFFICE));
        self::assertSame([], ScheduledPrune::run($scheduled['models']));
    }
}
