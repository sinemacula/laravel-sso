<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackCorrelator;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackParameters;
use Tests\Concerns\CapturesLogs;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for correlating an OpenID Connect callback; every refusal is
 * uncorrelated, so nothing is consumed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallbackCorrelator::class)]
#[CoversClass(CallbackParameters::class)]
final class CallbackCorrelatorTest extends TestCase
{
    use CapturesLogs;

    /** @var string A state of the package's shape: 43 base64url characters, the alphabet's last two among them. */
    private const string STATE = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE';

    /**
     * A `GET` whose `state` has the package's shape names its request by that
     * state, and by nothing else.
     *
     * @return void
     */
    public function testACallbackWithAWellFormedStateIsSolicited(): void
    {
        $correlation = $this->correlated('GET', 'code=the-code&state=' . self::STATE . '&iss=https%3A%2F%2Fop.example.test');

        self::assertTrue($correlation->isSolicited());
        self::assertSame(self::STATE, $correlation->state?->reveal());
        self::assertSame(hash('sha256', self::STATE), $correlation->stateDigest());
        self::assertNull($correlation->samlRequestId);
    }

    /**
     * Rows of `[method]`: what is not exactly `GET`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMethods(): iterable
    {
        yield from [
            'a post'     => ['POST'],
            'lower case' => ['get'],
            'a head'     => ['HEAD'],
            'empty'      => [''],
        ];
    }

    /**
     * Any method but exactly `GET` is uncorrelated, whatever its query.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideMethods')]
    public function testOnlyAGetIsCorrelated(string $method): void
    {
        self::assertTrue($this->correlated($method, 'state=' . self::STATE)->isUncorrelated());
    }

    /**
     * Rows of `[query]`: a query that names no request.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUncorrelatedQueries(): iterable
    {
        $state = self::STATE;

        yield from [
            'no query'                   => [''],
            'no state'                   => ['code=the-code'],
            'an empty state'             => ['state='],
            'a state of 42 characters'   => ['state=' . substr($state, 1)],
            'a state of 44 characters'   => ['state=' . $state . 'A'],
            'a padded state'             => ['state=' . substr($state, 1) . '%3D'],
            'a state padded past 43'     => ['state=' . $state . '%3D'],
            'a standard base64 plus'     => ['state=%2B' . substr($state, 1)],
            'a standard base64 slash'    => ['state=%2F' . substr($state, 1)],
            'a space'                    => ['state=+' . substr($state, 1)],
            'a dot'                      => ['state=.' . substr($state, 1)],
            'a trailing line feed'       => ['state=' . substr($state, 1) . '%0A'],
            'a repeated state'           => ['state=' . $state . '&state=' . $state],
            'a conflicting state'        => ['state=' . $state . '&state=other'],
            'a repeat once decoded'      => ['st%61te=' . $state . '&state=' . $state],
            'an array state'             => ['state[]=' . $state],
            'a state in another case'    => ['State=' . $state],
            'another parameter repeated' => ['state=' . $state . '&code=a&code=b'],
            'another array parameter'    => ['state=' . $state . '&code[x]=a'],
            'another parameter too long' => ['state=' . $state . '&extra=' . str_repeat('x', 2049)],
        ];
    }

    /**
     * Each is uncorrelated.
     *
     * @param  string  $query
     * @return void
     */
    #[DataProvider('provideUncorrelatedQueries')]
    public function testAQueryThatNamesNoRequestIsUncorrelated(string $query): void
    {
        self::assertTrue($this->correlated('GET', $query)->isUncorrelated());
    }

    /**
     * The state is read from the raw query, never from the posted fields.
     *
     * @return void
     */
    public function testReadsTheStateFromTheQueryAlone(): void
    {
        $correlation = app(CallbackCorrelator::class)->correlate(self::connection(), new CompletionRequest('GET', '', ['state' => self::STATE]));

        self::assertTrue($correlation->isUncorrelated());
    }

    /**
     * The caps come from the configuration, so a query within the defaults is
     * uncorrelated once its cap is lowered.
     *
     * @return void
     */
    public function testReadsTheCapsFromTheConfiguration(): void
    {
        $query = 'state=' . self::STATE . '&extra=' . str_repeat('x', 257);

        self::assertTrue($this->correlated('GET', $query)->isSolicited());

        config()->set('sso.oidc.max_callback_parameter_bytes', 256);

        self::assertTrue($this->correlated('GET', $query)->isUncorrelated());
    }

    /**
     * Correlating logs nothing, whether the callback is correlated or not.
     *
     * @return void
     */
    public function testLogsNothing(): void
    {
        $this->captureLogs();

        $this->correlated('GET', 'state=' . self::STATE);
        $this->correlated('GET', 'state=a&state=b');
        $this->correlated('POST', 'state=' . self::STATE);

        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * The correlation of what arrived.
     *
     * @param  string  $method
     * @param  string  $query
     * @return \SineMacula\Laravel\Sso\Protocols\Correlation
     */
    private function correlated(string $method, string $query): Correlation
    {
        return app(CallbackCorrelator::class)->correlate(self::connection(), new CompletionRequest($method, $query, []));
    }

    /**
     * A connection, which correlating does not read.
     *
     * @return \Tests\Fixtures\Protocols\IdentifiedConnection
     */
    private static function connection(): IdentifiedConnection
    {
        return new IdentifiedConnection('01jbcallbackcorrelator0000');
    }
}
