<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Jose;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\StrictJson;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for the strict JSON decoder (SSO-7.3, SSO-7.4): an object is read
 * whole, and anything else, a repeated member at any depth (compared once its
 * escapes are read) included, is refused, by each of its three readings; only
 * `decodeObject()` keeps a number's digits, and only `decodeAsWritten()` tells
 * an object from a list.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StrictJson::class)]
final class StrictJsonTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /**
     * Rows of `[json, members]`: objects read whole.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, mixed>}>
     */
    public static function provideObjects(): iterable
    {
        yield from [
            'empty'                          => ['{}', []],
            'with whitespace around'         => [" \t\n\r{\"a\":1} \n", ['a' => 1]],
            'nested'                         => ['{"a":{"b":[1,{"c":true}]}}', ['a' => ['b' => [1, ['c' => true]]]]],
            'one name in two objects'        => ['{"a":{"x":1},"b":{"x":2}}', ['a' => ['x' => 1], 'b' => ['x' => 2]]],
            'one name in objects of a list'  => ['{"keys":[{"kid":"a"},{"kid":"b"}]}', ['keys' => [['kid' => 'a'], ['kid' => 'b']]]],
            'a name as a value'              => ['{"a":"a","b":["a","a"]}', ['a' => 'a', 'b' => ['a', 'a']]],
            'escaped quotes and backslashes' => ['{"a\"b":"c\\\","d":"\"}"}', ['a"b' => 'c\\', 'd' => '"}']],
            'a large integer kept as digits' => ['{"exp":99999999999999999999}', ['exp' => '99999999999999999999']],
            'a fraction'                     => ['{"exp":1.5}', ['exp' => 1.5]],
            'names differing in case'        => ['{"a":1,"A":2}', ['a' => 1, 'A' => 2]],
            'a name again after its object'  => ['{"a":{"b":1},"b":2}', ['a' => ['b' => 1], 'b' => 2]],
            'a name again after its list'    => ['{"a":[{"b":1}],"b":2}', ['a' => [['b' => 1]], 'b' => 2]],
        ];
    }

    /**
     * An object is read whole.
     *
     * @param  string  $json
     * @param  array<array-key, mixed>  $members
     * @return void
     */
    #[DataProvider('provideObjects')]
    public function testAnObjectIsReadWhole(string $json, array $members): void
    {
        self::assertSame($members, StrictJson::decodeObject($json));
    }

    /**
     * Rows of `[json]`: what is refused.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'a repeated member'                => ['{"a":1,"a":1}'],
            'a repeated member, escaped'       => ['{"a":1,"\u0061":2}'],
            'a repeated member, surrogates'    => ['{"\ud83d\ude00":1,"😀":2}'],
            'a repeated member, nested'        => ['{"a":{"b":1,"b":2}}'],
            'a repeated member in a list item' => ['{"keys":[{"kid":"a","kid":"b"}]}'],
            'a repeated member after a list'   => ['{"a":[1,2],"b":3,"a":4}'],
            'a repeated empty name'            => ['{"":1,"":2}'],
            'a list'                           => ['[]'],
            'a string'                         => ['"a"'],
            'a number'                         => ['1'],
            'null'                             => ['null'],
            'empty'                            => [''],
            'malformed'                        => ['{"a":}'],
            'trailing text'                    => ['{"a":1} x'],
            'invalid UTF-8'                    => ["{\"a\":\"\xc3\x28\"}"],
            'nested too deep'                  => [str_repeat('{"a":', StrictJson::MAX_DEPTH) . '1' . str_repeat('}', StrictJson::MAX_DEPTH)],
        ];
    }

    /**
     * Anything but one object without a repeated member is refused.
     *
     * @param  string  $json
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testAnythingElseIsRefused(string $json): void
    {
        self::assertNull(StrictJson::decodeObject($json));
        self::assertNull(StrictJson::decodeMembers($json));
        self::assertNull(StrictJson::decodeAsWritten($json));
    }

    /**
     * Rows of `[json, members]`: what `decodeMembers()` reads, every number a
     * number.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, mixed>}>
     */
    public static function provideMembers(): iterable
    {
        yield from [
            'empty'                 => ['{}', []],
            'nested'                => ['{"a":{"b":[1,{"c":true}]}}', ['a' => ['b' => [1, ['c' => true]]]]],
            'a large number'        => ['{"sub":99999999999999999999}', ['sub' => 1.0E+20]],
            'a large number nested' => ['{"a":{"b":[99999999999999999999]}}', ['a' => ['b' => [1.0E+20]]]],
            'the digits of a large' => ['{"sub":"99999999999999999999"}', ['sub' => '99999999999999999999']],
            'an object as an array' => ['{"aud":{"0":"a"}}', ['aud' => ['a']]],
        ];
    }

    /**
     * `decodeMembers()` reads a number as a number, never its digits.
     *
     * @param  string  $json
     * @param  array<array-key, mixed>  $members
     * @return void
     */
    #[DataProvider('provideMembers')]
    public function testMembersKeepEveryNumberANumber(string $json, array $members): void
    {
        self::assertSame($members, StrictJson::decodeMembers($json));
    }

    /**
     * `decodeAsWritten()` keeps an object an object and a list a list, whatever
     * their names, and a number a number.
     *
     * @return void
     */
    public function testAsWrittenKeepsWhatJsonWrote(): void
    {
        $written = StrictJson::decodeAsWritten('{"list":["a"],"object":{"0":"a"},"empty":{},"none":[],"large":99999999999999999999,"text":"99999999999999999999"}');

        self::assertInstanceOf(\stdClass::class, $written);
        self::assertSame(['a'], $written->list);
        self::assertEquals((object) ['0' => 'a'], $written->object);
        self::assertInstanceOf(\stdClass::class, $written->object);
        self::assertInstanceOf(\stdClass::class, $written->empty);
        self::assertSame([], $written->none);
        self::assertSame(1.0E+20, $written->large);
        self::assertSame('99999999999999999999', $written->text);
    }

    /**
     * A name no object can hold is refused as written, and read otherwise.
     *
     * @return void
     */
    public function testANameNoObjectHoldsIsRefusedAsWritten(): void
    {
        $json = '{"' . chr(92) . 'u0000x":1}';

        self::assertSame(["\0x" => 1], StrictJson::decodeObject($json));
        self::assertSame(["\0x" => 1], StrictJson::decodeMembers($json));
        self::assertNull(StrictJson::decodeAsWritten($json));
    }

    /**
     * The deepest nesting accepted is the maximum, counting the object itself.
     *
     * @return void
     */
    public function testTheMaximumDepthIsAccepted(): void
    {
        $depth = StrictJson::MAX_DEPTH - 1;
        $json  = str_repeat('{"a":', $depth) . '1' . str_repeat('}', $depth);

        self::assertIsArray(StrictJson::decodeObject($json));
        self::assertSame(32, StrictJson::MAX_DEPTH);
    }

    /**
     * Rows of `[json]`: valid JSON, one document repeating no member and one
     * repeating a member PHP's decoder would keep the last of.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideDocumentsAtALimit(): iterable
    {
        yield from [
            'repeating no member' => ['{"a":"b","c":["d",{"e":"f"}]}'],
            'repeating a member'  => ['{"iss":"https://good.test","iss":"https://evil.test"}'],
        ];
    }

    /**
     * Every reading refuses a document when PCRE cannot tokenise it, whether or
     * not it repeats a member, for the failure itself; with the limit back, the
     * document is judged on what it holds.
     *
     * @param  string  $json
     * @return void
     */
    #[DataProvider('provideDocumentsAtALimit')]
    public function testADocumentPcreCannotTokenizeIsRefused(string $json): void
    {
        $jit       = ini_get('pcre.jit');
        $backtrack = ini_get('pcre.backtrack_limit');

        self::assertIsString($jit);
        self::assertIsString($backtrack);

        ini_set('pcre.jit', '0');
        ini_set('pcre.backtrack_limit', '1');

        try {
            $readings = [StrictJson::decodeObject($json), StrictJson::decodeMembers($json), StrictJson::decodeAsWritten($json)];
            $failure  = preg_last_error();
        } finally {
            ini_set('pcre.jit', $jit);
            ini_set('pcre.backtrack_limit', $backtrack);
        }

        self::assertSame([null, null, null], $readings);
        self::assertSame(PREG_BACKTRACK_LIMIT_ERROR, $failure);
    }

    /**
     * With its limits as they were, the document that repeats no member is read
     * by each reading again, so the refusal above was the limit's alone.
     *
     * @return void
     */
    public function testADocumentIsReadOnceTheLimitIsBack(): void
    {
        $json = '{"a":"b","c":["d",{"e":"f"}]}';

        self::assertSame(['a' => 'b', 'c' => ['d', ['e' => 'f']]], StrictJson::decodeObject($json));
        self::assertSame(['a' => 'b', 'c' => ['d', ['e' => 'f']]], StrictJson::decodeMembers($json));
        self::assertSame('b', StrictJson::decodeAsWritten($json)?->a);
    }
}
