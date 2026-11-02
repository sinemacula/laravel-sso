<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Jose;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;

/**
 * Unit tests for a connection's ID token algorithm allow-list (SSO-7.3): only
 * the asymmetric algorithms at 256 bits and above, never `none` or HMAC, each
 * with the key type and curve it needs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AlgorithmAllowList::class)]
final class AlgorithmAllowListTest extends TestCase
{
    /**
     * The algorithms a list may hold are these, with their curves.
     *
     * @return void
     */
    public function testTheAlgorithmsAreTheAsymmetricOnes(): void
    {
        self::assertSame([
            'RS256' => null, 'RS384' => null, 'RS512' => null,
            'PS256' => null, 'PS384' => null, 'PS512' => null,
            'ES256' => 'P-256', 'ES384' => 'P-384', 'ES512' => 'P-521',
        ], AlgorithmAllowList::ALGORITHMS);
    }

    /**
     * A list keeps each algorithm once, in the order given, and allows exactly
     * those, compared exactly.
     *
     * @return void
     */
    public function testAListAllowsExactlyItsAlgorithms(): void
    {
        $list = AlgorithmAllowList::of(['PS256', 'RS256', 'PS256']);

        self::assertSame(['PS256', 'RS256'], $list->names);
        self::assertTrue($list->allows('PS256'));
        self::assertTrue($list->allows('RS256'));
        self::assertFalse($list->allows('ES256'));
        self::assertFalse($list->allows('rs256'));
        self::assertFalse($list->allows('RS256 '));
    }

    /**
     * Rows of `[names]`: lists that are refused.
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function provideRefusedLists(): iterable
    {
        yield from [
            'none'         => [['none']],
            'None'         => [['RS256', 'None']],
            'HS256'        => [['HS256']],
            'HS384'        => [['HS384']],
            'HS512'        => [['HS512']],
            'lower case'   => [['rs256']],
            'EdDSA'        => [['EdDSA']],
            'RS1'          => [['RS1']],
            'not a string' => [[256]],
            'empty'        => [[]],
        ];
    }

    /**
     * `none`, HMAC, any other name and an empty list are refused.
     *
     * @param  array<array-key, mixed>  $names
     * @return void
     */
    #[DataProvider('provideRefusedLists')]
    public function testOtherAlgorithmsAreRefused(array $names): void
    {
        $this->expectException(\InvalidArgumentException::class);

        AlgorithmAllowList::of($names);
    }

    /**
     * Each algorithm names the key type and curve it needs; an unknown one
     * names none.
     *
     * @return void
     */
    public function testEachAlgorithmNamesItsKey(): void
    {
        self::assertSame(['RSA', 'RSA', 'EC', null], array_map(AlgorithmAllowList::keyTypeOf(...), ['RS256', 'PS512', 'ES384', 'HS256']));
        self::assertSame([null, 'P-256', 'P-384', 'P-521', null], array_map(AlgorithmAllowList::curveOf(...), ['RS256', 'ES256', 'ES384', 'ES512', 'HS256']));
    }
}
