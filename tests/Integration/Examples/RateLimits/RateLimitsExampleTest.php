<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RateLimits;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Sso\RateLimiting\RateLimitsCheck;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/rate-limits.md` (SSO-11.8, SSO-12.5), on the
 * shared example harness: the guide's published limits laid over the package's,
 * passing the `[rate_limits]` check and counted with the table and its
 * connection left to their defaults; the start route answering a full limit
 * `429` with the seconds to wait in `Retry-After`; and the application's own
 * sign-in hint counting its attempts through the package's limiter, all or
 * none, each value in its canonical form. Each refusal is shown: a flow left
 * out of the published block fails closed and is reported, a limit the package
 * does not count is reported, and a full limit refuses the attempt, counts it
 * against nothing and frees when its window ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(AttemptSubject::class)]
#[CoversClass(AttemptResult::class)]
#[CoversClass(RateLimitsCheck::class)]
final class RateLimitsExampleTest extends ExampleTestCase
{
    /** @var string The route the guide's application starts a sign-in on. */
    private const string ROUTE = '/auth/sso/start';

    /** @var string The address of an office behind one NAT address. */
    private const string OFFICE = '203.0.113.7';

    /** @var string The address of another client. */
    private const string ELSEWHERE = '198.51.100.9';

    /** @var string What the check and the limiter say of a flow with no limits. */
    private const string REDEMPTION_MISSING = '`sso.rate_limits.redemption.per_ip` must be an array of `max` (1 to 1000000) and `decay_seconds` (1 to 86400).';

    /** @var string The connection the start route starts through. */
    private string $connectionId;

    /**
     * Serve the guide's route, and make the connection it starts through.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Route::group([], __DIR__ . '/routes.php');

        $this->connectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));
    }

    /**
     * Under the published block, which leaves out the table and its connection,
     * the check finds every limit, and the office's address may start sixty
     * sign-ins in the minute, not sixty-one, while another address may still
     * start one.
     *
     * @return void
     */
    public function testThePublishedLimitsAreTheOnesCounted(): void
    {
        $this->publishConfiguration();

        self::assertStringContainsString('[rate_limits] OK', self::checked()[1]);

        $limiter = app(AttemptLimiter::class);

        for ($attempt = 1; $attempt <= 60; $attempt++) {
            self::assertTrue($limiter->attempt(AttemptSubject::authorizationRequest(self::OFFICE))->isAllowed(), "Start {$attempt} was refused.");
        }

        $refused = $limiter->attempt(AttemptSubject::authorizationRequest(self::OFFICE));

        self::assertTrue($refused->isRateLimited());
        self::assertSame(60, $refused->retryAfter);
        self::assertTrue($limiter->attempt(AttemptSubject::authorizationRequest(self::ELSEWHERE))->isAllowed());
    }

    /**
     * A published block that leaves out a flow fails the check under
     * `[rate_limits]`, naming the key, and every attempt at that flow throws,
     * while the flows it keeps are counted as before.
     *
     * @return void
     */
    public function testAFlowLeftOutOfThePublishedBlockFailsClosed(): void
    {
        $this->publishConfiguration();

        /** @var array<string, mixed> $limits */
        $limits = config('sso.rate_limits');

        unset($limits['redemption']);

        config()->set('sso.rate_limits', $limits);

        [$code, $output] = self::checked();

        self::assertSame(1, $code);
        self::assertStringContainsString('[rate_limits] ' . self::REDEMPTION_MISSING, $output);
        self::assertTrue(app(AttemptLimiter::class)->attempt(AttemptSubject::authorizationRequest(self::OFFICE))->isAllowed());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::REDEMPTION_MISSING);

        app(AttemptLimiter::class)->attempt(AttemptSubject::redemption(self::OFFICE));
    }

    /**
     * A limit the package does not count, a `per_connection` under
     * `redemption`, fails the check, though redemptions are still counted by
     * the limits they have.
     *
     * @return void
     */
    public function testALimitThePackageDoesNotCountIsReported(): void
    {
        $this->publishConfiguration();

        config()->set('sso.rate_limits.redemption.per_connection', ['max' => 30, 'decay_seconds' => 60]);

        [$code, $output] = self::checked();

        self::assertSame(1, $code);
        self::assertStringContainsString('[rate_limits] Remove `sso.rate_limits.redemption.per_connection`: the package counts no such limit, so it limits nothing.', $output);
        self::assertTrue(app(AttemptLimiter::class)->attempt(AttemptSubject::redemption(self::OFFICE))->isAllowed());
    }

    /**
     * Once the office's address has used its two starts, the next, fifteen
     * seconds into the minute, is answered `429` with the forty-five seconds
     * left in `Retry-After` and the flow's one `rate_limited` failure; another
     * address still starts, and the office starts again once the minute ends.
     *
     * @return void
     */
    public function testAFullLimitIsAnsweredWithItsWait(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 2, 'decay_seconds' => 60]);

        $failed = $this->failures();

        $this->startSignInFrom(self::OFFICE)->assertOk();
        $this->startSignInFrom(self::OFFICE)->assertOk();
        $this->clock->advance(15);

        $limited = $this->startSignInFrom(self::OFFICE)->assertStatus(429);

        self::assertEquals(['error' => 'rate_limited'], $limited->json());
        self::assertSame('45', $limited->headers->get('Retry-After'));
        self::assertSame([FailureReason::RATE_LIMITED], array_map(static fn (FlowFailed $event): FailureReason => $event->reason, $failed->getArrayCopy()));

        $this->startSignInFrom(self::ELSEWHERE)->assertOk();
        $this->clock->advance(45);

        $started = $this->startSignInFrom(self::OFFICE)->assertOk();

        self::assertNull($started->headers->get('Retry-After'));
        self::assertCount(1, $failed);
    }

    /**
     * The application's own hint counts each attempt against the address and
     * the email's domain, all or none: the domain is counted in its ASCII form,
     * in lower case and without a trailing dot, so a third attempt at it is
     * refused, counting against neither; the address then has room for its
     * three, one with no domain, before it is refused too; and a minute on, the
     * domain may be tried again.
     *
     * @return void
     */
    public function testTheApplicationsOwnAttemptIsCountedAllOrNone(): void
    {
        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 3, 'decay_seconds' => 60]);
        config()->set('sso.rate_limits.authorization_request.per_email_domain', ['max' => 2, 'decay_seconds' => 60]);

        self::assertTrue(self::hint(self::OFFICE, 'Bücher.example')->isAllowed());
        self::assertTrue(self::hint(self::ELSEWHERE, 'xn--bcher-kva.example')->isAllowed());

        $domainFull = self::hint(self::ELSEWHERE, 'bücher.example.');

        self::assertTrue($domainFull->isRateLimited());
        self::assertSame(FailureReason::RATE_LIMITED, $domainFull->reason);
        self::assertSame(60, $domainFull->retryAfter);

        self::assertTrue(self::hint(self::ELSEWHERE, null)->isAllowed());
        self::assertTrue(self::hint(self::ELSEWHERE, 'example.org')->isAllowed());

        $addressFull = self::hint(self::ELSEWHERE, 'example.net');

        self::assertTrue($addressFull->isRateLimited());
        self::assertSame(60, $addressFull->retryAfter);

        $this->clock->advance(60);

        $allowed = self::hint(self::ELSEWHERE, 'BÜCHER.example');

        self::assertTrue($allowed->isAllowed());
        self::assertNull($allowed->reason);
        self::assertNull($allowed->retryAfter);
    }

    /**
     * Lay the guide's published configuration over the package's, key by key,
     * as Laravel merges a published file with a package's.
     *
     * @return void
     */
    private function publishConfiguration(): void
    {
        /** @var array<string, mixed> $published */
        $published = require __DIR__ . '/config/sso.php';

        /** @var array<string, mixed> $package */
        $package = config('sso');

        config()->set('sso', array_replace($package, $published));
    }

    /**
     * Post a sign-in start to the guide's route from the address, as the client
     * does.
     *
     * @param  string  $ip
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function startSignInFrom(string $ip): TestResponse
    {
        return $this->withServerVariables(['REMOTE_ADDR' => $ip])->postJson(self::ROUTE, ['connection' => $this->connectionId]);
    }

    /**
     * Every `FlowFailed` reported from now on.
     *
     * @return \ArrayObject<int, \SineMacula\Laravel\Sso\Events\FlowFailed>
     */
    private function failures(): \ArrayObject
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Sso\Events\FlowFailed> $failed */
        $failed = new \ArrayObject;

        Event::listen(FlowFailed::class, static function (FlowFailed $event) use ($failed): void {
            $failed->append($event);
        });

        return $failed;
    }

    /**
     * Run the application's sign-in hint for a request from the address with
     * the email's domain, and answer what the limiter decided.
     *
     * @param  string  $ip
     * @param  ?string  $emailDomain
     * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
     */
    private static function hint(string $ip, ?string $emailDomain): AttemptResult
    {
        $result = self::atHint([
            'request' => Request::create('/auth/sso/hint', 'POST', server: ['REMOTE_ADDR' => $ip]),
            'domain'  => $emailDomain,
        ]);

        self::assertInstanceOf(AttemptResult::class, $result);

        return $result;
    }

    /**
     * Run the guide's sign-in hint with its input in scope.
     *
     * @param  array{request: \Illuminate\Http\Request, domain: ?string}  $input
     * @return mixed
     */
    private static function atHint(array $input): mixed
    {
        return require __DIR__ . '/sign-in-hint.php';
    }

    /**
     * Run `sso:check`, and answer its exit code and its output.
     *
     * @return array{0: int, 1: string}
     */
    private static function checked(): array
    {
        $code = Artisan::call('sso:check');

        return [$code, Artisan::output()];
    }
}
