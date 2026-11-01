<?php

declare(strict_types = 1);

namespace Tests\Feature\Config\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Config\Checks\EndpointsCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[endpoints]`: checked while the package is in use, a base
 * URL required and never with a query, and each path pattern absolute, holding
 * `{connection}` once and distinct from the others.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EndpointsCheck::class)]
final class EndpointsCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * Not checked while the package is not in use, though no base URL is set;
     * the default patterns with a base URL pass once it is.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        self::assertNull($this->problemsOf(EndpointsCheck::class));

        $this->useThePackage();

        self::assertSame([], $this->problemsOf(EndpointsCheck::class));
    }

    /**
     * Rows of `[settings, problems]`: endpoint configurations and what each
     * reports.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function provideConfigurations(): iterable
    {
        $base = '`sso.endpoints.base_url` must be an absolute https URL (or http on 127.0.0.1 or [::1]) with no user information, fragment or wildcard, or query.';
        $path = static fn (string $endpoint): string => "`sso.endpoints.paths.{$endpoint}` must be an absolute path holding `{connection}` once,"
            . ' with no query, fragment, other placeholder or dot segment.';

        yield 'a base URL with a path' => [['sso.endpoints.base_url' => 'https://api.example.com/v1'], []];
        yield 'a loopback base URL' => [['sso.endpoints.base_url' => 'http://127.0.0.1:8000'], []];
        yield 'no base URL' => [['sso.endpoints.base_url' => null], [$base]];
        yield 'a plain http base URL' => [['sso.endpoints.base_url' => 'http://api.example.com'], [$base]];
        yield 'a base URL with a query' => [['sso.endpoints.base_url' => 'https://api.example.com?x=1'], [$base]];
        yield 'a relative pattern' => [['sso.endpoints.paths.callback' => 'sso/{connection}/callback'], [$path('callback')]];
        yield 'a pattern without the connection' => [['sso.endpoints.paths.metadata' => '/sso/metadata'], [$path('metadata')]];
        yield 'a pattern with it twice' => [['sso.endpoints.paths.metadata' => '/sso/{connection}/{connection}'], [$path('metadata')]];
        yield 'another placeholder' => [['sso.endpoints.paths.callback' => '/sso/{tenant}/{connection}'], [$path('callback')]];
        yield 'a query' => [['sso.endpoints.paths.callback' => '/sso/{connection}?x=1'], [$path('callback')]];
        yield 'a dot segment' => [['sso.endpoints.paths.assertion_consumer_service' => '/sso/../{connection}'], [$path('assertion_consumer_service')]];
        yield 'not a string' => [['sso.endpoints.paths.callback' => null], [$path('callback')]];
        yield 'two the same' => [
            ['sso.endpoints.paths.callback' => '/auth/sso/connections/{connection}/assertions'],
            ['`sso.endpoints.paths.assertion_consumer_service` and `sso.endpoints.paths.callback` must differ.'],
        ];
    }

    /**
     * Each configuration reports exactly its problems.
     *
     * @param  array<string, mixed>  $settings
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideConfigurations')]
    public function testReportsEachProblem(array $settings, array $problems): void
    {
        $this->useThePackage();

        config()->set($settings);

        self::assertSame($problems, $this->problemsOf(EndpointsCheck::class));
    }
}
