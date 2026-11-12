<?php

declare(strict_types = 1);

namespace Tests\Unit\Links;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Unit tests for the default linker, which resolves everything to `absent`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoLinks::class)]
final class NoLinksTest extends TestCase
{
    /**
     * Rows of `[result, client]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Results\VerifiedResult, 1: \SineMacula\Laravel\Sso\Http\ClientContext}>
     */
    public static function provideResolutions(): iterable
    {
        yield 'a full sign-in for a browser' => [ExampleResults::full(), new ClientContext('203.0.113.7', 'Example/1.0')];
        yield 'a bare link for no client' => [ExampleResults::bare(Purpose::LINK), new ClientContext(null, null)];
        $elsewhere = ExampleResults::full(Purpose::REAUTHENTICATE, '01jbanotherconnection00000');

        yield 'a reauthentication through another connection' => [$elsewhere, new ClientContext('2001:db8::1', null)];
    }

    /**
     * Whatever the result and the client, nothing is linked.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     */
    #[DataProvider('provideResolutions')]
    public function testResolvesNothing(VerifiedResult $result, ClientContext $client): void
    {
        $resolution = (new NoLinks)->resolve($result, $client);

        self::assertTrue($resolution->isAbsent());
        self::assertNull($resolution->identity);
        self::assertNull($resolution->linkId);
    }
}
