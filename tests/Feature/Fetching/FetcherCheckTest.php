<?php

declare(strict_types = 1);

namespace Tests\Feature\Fetching;

use GuzzleHttp\Handler\CurlHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Fetching\FetcherCheck;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[fetcher]`: checked while the package is in use, each
 * setting reported with the message the fetcher would fail closed with, a
 * malformed refused range named by its key, a connect timeout longer than the
 * timeout, and a missing cURL transport (SSO-2.9).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FetcherCheck::class)]
final class FetcherCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * Not checked while the package is not in use, however malformed; the
     * shipped defaults pass once it is.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        config()->set('sso.fetcher.timeout_seconds', 'ten');
        config()->set('sso.fetcher.refused_ranges', 'none');

        self::assertNull($this->problemsOf(FetcherCheck::class));

        $this->useThePackage();
        config()->set('sso.fetcher.timeout_seconds', 10);
        config()->set('sso.fetcher.refused_ranges', []);

        self::assertSame([], $this->problemsOf(FetcherCheck::class));
    }

    /**
     * A malformed protocol switch counts as the package in use, so the
     * fetcher's settings are checked rather than skipped.
     *
     * @return void
     */
    public function testAppliesOverAMalformedProtocolSwitch(): void
    {
        config()->set('sso.features.oidc', 'yes');
        config()->set('sso.fetcher.max_redirects', 11);

        self::assertSame(['sso.fetcher.max_redirects must be an integer from 0 to 10.'], $this->problemsOf(FetcherCheck::class));
    }

    /**
     * Rows of `[settings, problems]`: fetcher settings and what each reports.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function provideSettings(): iterable
    {
        $range = ' must be a CIDR range: an IPv4 address with /0 to /32, or an IPv6 address with /0 to /128.';

        yield from [
            'valid'                      => [['timeout_seconds' => 30, 'connect_timeout_seconds' => 30, 'refused_ranges' => ['8.8.8.0/24', '2606:4700::/32']], []],
            'a malformed timeout'        => [['timeout_seconds' => 0], ['sso.fetcher.timeout_seconds must be an integer from 1 to 60.']],
            'a malformed connect'        => [['connect_timeout_seconds' => 31], ['sso.fetcher.connect_timeout_seconds must be an integer from 1 to 30.']],
            'a malformed size cap'       => [['max_response_bytes' => 512], ['sso.fetcher.max_response_bytes must be an integer from 1024 to 10485760.']],
            'a malformed redirect limit' => [['max_redirects' => -1], ['sso.fetcher.max_redirects must be an integer from 0 to 10.']],
            'a list that is not a list'  => [['refused_ranges' => '10.0.0.0/8'], ['sso.fetcher.refused_ranges must be a list of CIDR ranges.']],
            'a bad cidr'                 => [['refused_ranges' => ['8.8.8.0/24', '10.0.0.0/33']], ['sso.fetcher.refused_ranges.1' . $range]],
            'connect past the timeout'   => [['timeout_seconds' => 5, 'connect_timeout_seconds' => 6], [FetcherSettings::CONNECT_TIMEOUT_EXCEEDS_TIMEOUT]],
            'every problem at once'      => [
                ['timeout_seconds' => 'ten', 'connect_timeout_seconds' => 0, 'max_response_bytes' => '1 MiB', 'max_redirects' => 99, 'refused_ranges' => ['localhost']],
                [
                    'sso.fetcher.timeout_seconds must be an integer from 1 to 60.',
                    'sso.fetcher.connect_timeout_seconds must be an integer from 1 to 30.',
                    'sso.fetcher.max_response_bytes must be an integer from 1024 to 10485760.',
                    'sso.fetcher.max_redirects must be an integer from 0 to 10.',
                    'sso.fetcher.refused_ranges.0' . $range,
                ],
            ],
        ];
    }

    /**
     * Each setting reports exactly its problems, every one in a run, and a
     * malformed timeout is not reported a second time as a connect timeout past
     * it.
     *
     * @param  array<string, mixed>  $settings
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideSettings')]
    public function testReportsEachProblem(array $settings, array $problems): void
    {
        $this->useThePackage();

        foreach ($settings as $key => $value) {
            config()->set('sso.fetcher.' . $key, $value);
        }

        self::assertSame($problems, $this->problemsOf(FetcherCheck::class));
    }

    /**
     * Settings that are not configured at all take their defaults and pass.
     *
     * @return void
     */
    public function testUnsetSettingsPass(): void
    {
        $this->useThePackage();

        config()->set('sso.fetcher', []);

        self::assertSame([], $this->problemsOf(FetcherCheck::class));
    }

    /**
     * Rows of `[curl loaded, handler exists]`: each way the cURL transport can
     * be missing.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideMissingTransports(): iterable
    {
        yield from [
            'no ext-curl'           => [false, true],
            'no cURL handler class' => [true, false],
            'neither'               => [false, false],
        ];
    }

    /**
     * A missing `ext-curl`, or a missing cURL handler, is reported with why the
     * fetcher needs it, rather than letting it fall back to PHP streams.
     *
     * @param  bool  $curlLoaded
     * @param  bool  $handlerExists
     * @return void
     */
    #[DataProvider('provideMissingTransports')]
    public function testReportsAMissingCurlTransport(bool $curlLoaded, bool $handlerExists): void
    {
        $this->useThePackage();

        $check = new FetcherCheck(
            new FetcherSettings(config()),
            static fn (string $extension): bool => $extension === 'curl' ? $curlLoaded : extension_loaded($extension),
            static fn (string $class): bool => $class === CurlHandler::class ? $handlerExists : class_exists($class),
        );

        $this->app?->instance(FetcherCheck::class, $check);

        self::assertSame([FetcherCheck::NO_CURL], $this->problemsOf(FetcherCheck::class));
    }

    /**
     * The check asks for the `curl` extension and Guzzle's cURL handler class
     * by name.
     *
     * @return void
     */
    public function testAsksForCurlAndTheCurlHandler(): void
    {
        $this->useThePackage();

        /** @var \ArrayObject<int, string> $asked */
        $asked = new \ArrayObject;

        $check = new FetcherCheck(
            new FetcherSettings(config()),
            static function (string $extension) use ($asked): bool {
                $asked->append($extension);

                return true;
            },
            static function (string $class) use ($asked): bool {
                $asked->append($class);

                return true;
            },
        );

        $this->app?->instance(FetcherCheck::class, $check);

        self::assertSame([], $this->problemsOf(FetcherCheck::class));
        self::assertSame(['curl', CurlHandler::class], $asked->getArrayCopy());
    }
}
