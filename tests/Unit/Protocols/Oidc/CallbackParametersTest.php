<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\CallbackParameters;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests for reading an OpenID Connect callback's raw query (SSO-7.1): the
 * splitting and form decoding; every refusal (empty, repeated once decoded,
 * array-shaped, over each cap at, under and over, invalid UTF-8, a control
 * character); unknown names ignored; and the values shown by no dump, JSON
 * encoding or serialisation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallbackParameters::class)]
final class CallbackParametersTest extends TestCase
{
    use DumpsValues;

    /**
     * Each parameter it reads is given through its accessor.
     *
     * @return void
     */
    public function testReadsEachParameterItKnows(): void
    {
        $parameters = self::parsed('code=the-code&state=the-state&iss=the-iss&error=the-error');

        self::assertSame(
            ['the-code', 'the-state', 'the-iss', 'the-error'],
            [$parameters->code(), $parameters->state(), $parameters->iss(), $parameters->error()],
        );
    }

    /**
     * A parameter that did not arrive is `null`.
     *
     * @return void
     */
    public function testAParameterThatDidNotArriveIsNull(): void
    {
        $parameters = self::parsed('code=the-code');

        self::assertSame(['the-code', null, null, null], [$parameters->code(), $parameters->state(), $parameters->iss(), $parameters->error()]);
    }

    /**
     * Names and values are form-decoded: `+` is a space and a percent-encoded
     * byte is the byte.
     *
     * @return void
     */
    public function testDecodesNamesAndValuesAsAForm(): void
    {
        $parameters = self::parsed('co%64e=a+b%2Fc&iss=https%3A%2F%2Fop.example.test%2Ft');

        self::assertSame(['a b/c', 'https://op.example.test/t'], [$parameters->code(), $parameters->iss()]);
    }

    /**
     * A pair splits at its first `=`, and a segment with none is a name with an
     * empty value.
     *
     * @return void
     */
    public function testSplitsEachPairAtItsFirstEquals(): void
    {
        $parameters = self::parsed('code=a=b&state==c&iss');

        self::assertSame(['a=b', '=c', ''], [$parameters->code(), $parameters->state(), $parameters->iss()]);
    }

    /**
     * Empty segments are ignored, at either end and between pairs, and count
     * towards nothing.
     *
     * @return void
     */
    public function testIgnoresEmptySegments(): void
    {
        $parameters = self::parsed('&&code=a&&&state=b&', ['max_callback_parameters' => 4]);

        self::assertSame(['a', 'b'], [$parameters->code(), $parameters->state()]);
    }

    /**
     * A name it does not read is ignored, and names are compared exactly, so
     * `State` and `CODE` are not `state` and `code`.
     *
     * @return void
     */
    public function testIgnoresNamesItDoesNotRead(): void
    {
        $parameters = self::parsed('State=other&CODE=other&session_state=other&state=the-state');

        self::assertSame(['the-state', null], [$parameters->state(), $parameters->code()]);
    }

    /**
     * Rows of `[query]`: each query refused whatever the caps are.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedQueries(): iterable
    {
        yield from [
            'empty'                       => [''],
            'nothing but separators'      => ['&&&'],
            'a repeated state'            => ['state=a&state=a'],
            'a repeated code'             => ['code=a&code=a'],
            'a repeated iss'              => ['iss=a&iss=a'],
            'a repeated error'            => ['error=a&error=a'],
            'conflicting values'          => ['state=a&state=b'],
            'a repeat once decoded'       => ['st%61te=a&state=a'],
            'a repeat of an unknown name' => ['extra=a&extra=b'],
            'a repeated empty name'       => ['=a&=b'],
            'a repeated numeric name'     => ['1=a&1=b'],
            'an array state'              => ['state[]=a'],
            'an encoded array state'      => ['state%5B%5D=a'],
            'a keyed code'                => ['code[x]=a'],
            'an opening bracket alone'    => ['a[=b'],
            'a closing bracket alone'     => ['a]=b'],
        ];
    }

    /**
     * Each query is refused.
     *
     * @param  string  $query
     * @return void
     */
    #[DataProvider('provideRefusedQueries')]
    public function testRefusesTheQuery(string $query): void
    {
        self::assertNull(CallbackParameters::parse($query, self::limits()));
    }

    /**
     * Names that only look alike are different names: an empty name is ignored,
     * `1` and `01` differ, and a bracket in a value is not array-shaped.
     *
     * @return void
     */
    public function testAcceptsNamesThatOnlyLookAlike(): void
    {
        $parameters = self::parsed('=a&1=b&01=c&code=d[e]');

        self::assertSame('d[e]', $parameters->code());
    }

    /**
     * Rows of `[query, accepted, limits]`: a query at, under and over each cap,
     * default and configured.
     *
     * @return iterable<string, array{0: string, 1: bool, 2: array<string, int>}>
     */
    public static function provideCaps(): iterable
    {
        yield from [
            'a value under the cap'            => ['code=' . str_repeat('x', 2047), true, []],
            'a value at the cap'               => ['code=' . str_repeat('x', 2048), true, []],
            'a value over the cap'             => ['code=' . str_repeat('x', 2049), false, []],
            'a name under the cap'             => [str_repeat('n', 2047) . '=a', true, []],
            'a name at the cap'                => [str_repeat('n', 2048) . '=a', true, []],
            'a name over the cap'              => [str_repeat('n', 2049) . '=a', false, []],
            'a decoded value at the cap'       => ['code=' . str_repeat('%41', 2048), true, []],
            'a decoded value over the cap'     => ['code=' . str_repeat('%41', 2049), false, []],
            'a decoded name at the cap'        => [str_repeat('%41', 2048) . '=a', true, []],
            'a decoded name over the cap'      => [str_repeat('%41', 2049) . '=a', false, []],
            'a query under the cap'            => [self::queryOf(8191), true, []],
            'a query at the cap'               => [self::queryOf(8192), true, []],
            'a query over the cap'             => [self::queryOf(8193), false, []],
            'a query with a raw length over'   => ['a=' . str_repeat('+', 2048) . '&b=' . str_repeat('%20', 2048) . '&c=' . str_repeat('x', 2048), false, []],
            'parameters under the cap'         => [self::parametersOf(15), true, []],
            'parameters at the cap'            => [self::parametersOf(16), true, []],
            'parameters over the cap'          => [self::parametersOf(17), false, []],
            'a value at a configured cap'      => ['code=' . str_repeat('x', 256), true, ['max_callback_parameter_bytes' => 256]],
            'a value over a configured cap'    => ['code=' . str_repeat('x', 257), false, ['max_callback_parameter_bytes' => 256]],
            'a query at a configured cap'      => ['a=' . str_repeat('x', 1022), true, ['max_callback_query_bytes' => 1024]],
            'a query over a configured cap'    => ['a=' . str_repeat('x', 1023), false, ['max_callback_query_bytes' => 1024]],
            'parameters at a configured cap'   => [self::parametersOf(4), true, ['max_callback_parameters' => 4]],
            'parameters over a configured cap' => [self::parametersOf(5), false, ['max_callback_parameters' => 4]],
        ];
    }

    /**
     * A query is refused only over a cap: its raw length for the whole query,
     * its decoded length for a name or value, and its segments for the count.
     *
     * @param  string  $query
     * @param  bool  $accepted
     * @param  array<string, int>  $limits
     * @return void
     */
    #[DataProvider('provideCaps')]
    public function testHoldsTheQueryToEachCap(string $query, bool $accepted, array $limits): void
    {
        self::assertSame($accepted, CallbackParameters::parse($query, self::limits($limits)) !== null);
    }

    /**
     * Rows of `[encoded, accepted]`: what a decoded value or name is refused or
     * accepted for holding.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideText(): iterable
    {
        yield from [
            'a NUL'                => ['%00', false],
            'a C0 control'         => ['%01', false],
            'a tab'                => ['%09', false],
            'a line feed'          => ['%0A', false],
            'a carriage return'    => ['%0D', false],
            'the last C0 control'  => ['%1F', false],
            'a space'              => ['%20', true],
            'a tilde'              => ['%7E', true],
            'DEL'                  => ['%7F', false],
            'the first C1 control' => ['%C2%80', false],
            'the last C1 control'  => ['%C2%9F', false],
            'a no-break space'     => ['%C2%A0', true],
            'an accented letter'   => ['caf%C3%A9', true],
            'a stray byte'         => ['%FF', false],
            'an overlong encoding' => ['%C0%80', false],
            'a surrogate'          => ['%ED%A0%80', false],
            'a truncated sequence' => ['%C3', false],
        ];
    }

    /**
     * A value that is not valid UTF-8, or holds a control character, is
     * refused; other text is accepted.
     *
     * @param  string  $encoded
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideText')]
    public function testHoldsAValueToBeingText(string $encoded, bool $accepted): void
    {
        self::assertSame($accepted, CallbackParameters::parse('code=a' . $encoded, self::limits()) !== null);
    }

    /**
     * A name is held to the same.
     *
     * @param  string  $encoded
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideText')]
    public function testHoldsANameToBeingText(string $encoded, bool $accepted): void
    {
        self::assertSame($accepted, CallbackParameters::parse('a' . $encoded . '=b', self::limits()) !== null);
    }

    /**
     * No dump shows a value it holds or one it ignored; each shows only the
     * names it reads.
     *
     * @return void
     */
    public function testNoDumpShowsAValue(): void
    {
        $parameters = self::parsed('code=value-of-code&state=value-of-state&iss=value-of-iss&error=value-of-error&extra=value-of-extra');

        foreach (self::dumps($parameters) as $dump) {
            self::assertStringNotContainsString('value-of-', $dump);
        }

        self::assertSame(
            ['code' => '[redacted]', 'state' => '[redacted]', 'iss' => '[redacted]', 'error' => '[redacted]'],
            $parameters->__debugInfo(),
        );
    }

    /**
     * JSON encoding shows the same as a dump, never a value.
     *
     * @return void
     */
    public function testJsonShowsNoValue(): void
    {
        $parameters = self::parsed('code=value-of-code');

        self::assertSame(['code' => '[redacted]'], $parameters->jsonSerialize());
        self::assertStringNotContainsString('value-of-', (string) json_encode($parameters));
    }

    /**
     * It refuses to be serialised.
     *
     * @return void
     */
    public function testRefusesToBeSerialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A callback\'s parameters cannot be serialised.');

        serialize(self::parsed('code=value-of-code'));
    }

    /**
     * It refuses to be unserialised.
     *
     * @return void
     */
    public function testRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A callback\'s parameters cannot be unserialised.');

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(CallbackParameters::class), CallbackParameters::class));
    }

    /**
     * The parameters of a query that is not refused.
     *
     * @param  string  $query
     * @param  array<string, int>  $limits
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\CallbackParameters
     */
    private static function parsed(string $query, array $limits = []): CallbackParameters
    {
        $parameters = CallbackParameters::parse($query, self::limits($limits));

        self::assertNotNull($parameters);

        return $parameters;
    }

    /**
     * The limits with the values given under `sso.oidc`, defaults otherwise.
     *
     * @param  array<string, int>  $oidc
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits
     */
    private static function limits(array $oidc = []): OidcLimits
    {
        return new OidcLimits(new Repository(['sso' => ['oidc' => $oidc]]));
    }

    /**
     * A query of exactly the bytes given, of four parameters, none longer than
     * its cap.
     *
     * @param  int  $bytes
     * @return string
     */
    private static function queryOf(int $bytes): string
    {
        $head = 'a=' . str_repeat('x', 2048) . '&b=' . str_repeat('x', 2048) . '&c=' . str_repeat('x', 2048) . '&d=';

        return $head . str_repeat('x', $bytes - strlen($head));
    }

    /**
     * A query of exactly the parameters given.
     *
     * @param  int  $count
     * @return string
     */
    private static function parametersOf(int $count): string
    {
        return implode('&', array_map(static fn (int $index): string => 'p' . $index . '=1', range(1, $count)));
    }
}
