<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitStore;

/**
 * Query budgets for the default attempt limiter, counted per counter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RateLimitStore::class)]
final class AttemptLimiterQueryBudgetTest extends PerformanceContractTestCase
{
    /** @var string The IP address every attempt comes from. */
    private const string IP = '203.0.113.7';

    /** @var string The email domain every authorisation request gives. */
    private const string DOMAIN = 'example.com';

    /**
     * Per counter: an update that finds nothing, then the insert.
     *
     * @return void
     */
    public function testTheFirstAttemptCreatesEachCounter(): void
    {
        $result = $this->assertQueryBudget(0, 4, fn (): AttemptResult => $this->attempt($this->request()));

        self::assertTrue($result->isAllowed());
    }

    /**
     * An attempt in a live window is one update per counter and no read.
     *
     * @return void
     */
    public function testAnAttemptInALiveWindowIsOneUpdatePerCounter(): void
    {
        $this->attempt($this->request());

        $result = $this->assertQueryBudget(0, 2, fn (): AttemptResult => $this->attempt($this->request()));

        self::assertTrue($result->isAllowed());
    }

    /**
     * An ended window restarts each counter in the same one update.
     *
     * @return void
     */
    public function testAnAttemptInAnEndedWindowIsOneUpdatePerCounter(): void
    {
        $this->attempt($this->request());
        $this->clock->advance(60);

        $result = $this->assertQueryBudget(0, 2, fn (): AttemptResult => $this->attempt($this->request()));

        self::assertTrue($result->isAllowed());
    }

    /**
     * The full counter's update, the insert its key refuses, the update again
     * and a read of the window's end.
     *
     * @return void
     */
    public function testARefusedAttemptStopsAtTheFullCounter(): void
    {
        $this->attempt(AttemptSubject::redemption(new ClientContext(self::IP, null)));
        $this->attempt(AttemptSubject::redemption(new ClientContext(self::IP, null)));

        $result = $this->assertQueryBudget(1, 3, fn (): AttemptResult => $this->attempt(AttemptSubject::redemption(new ClientContext(self::IP, null))));

        self::assertTrue($result->isRateLimited());
    }

    /**
     * The earlier counter's two statements, the full counter's four and one
     * update giving the slot back.
     *
     * @return void
     */
    public function testARefusalByALaterLimitGivesTheEarlierSlotBack(): void
    {
        $this->attempt(AttemptSubject::authorizationRequest(new ClientContext(null, null), self::DOMAIN));
        $this->attempt(AttemptSubject::authorizationRequest(new ClientContext(null, null), self::DOMAIN));

        $result = $this->assertQueryBudget(1, 6, fn (): AttemptResult => $this->attempt($this->request()));

        self::assertTrue($result->isRateLimited());
    }

    /**
     * Allow two redemptions per IP and two requests per email domain a minute.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('sso.rate_limits.redemption.per_ip', ['max' => 2, 'decay_seconds' => 60]);
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 10, 'decay_seconds' => 60]);
        config()->set('sso.rate_limits.authorization_request.per_email_domain', ['max' => 2, 'decay_seconds' => 60]);
    }

    /**
     * An authorisation request from the IP for the email domain.
     *
     * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject
     */
    private function request(): AttemptSubject
    {
        return AttemptSubject::authorizationRequest(new ClientContext(self::IP, null), self::DOMAIN);
    }

    /**
     * Make the attempt through the container's limiter.
     *
     * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
     */
    private function attempt(AttemptSubject $subject): AttemptResult
    {
        $limiter = $this->app?->make(AttemptLimiter::class);

        self::assertInstanceOf(AttemptLimiter::class, $limiter);

        return $limiter->attempt($subject);
    }
}
