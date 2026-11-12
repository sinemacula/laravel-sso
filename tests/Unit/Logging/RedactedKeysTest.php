<?php

declare(strict_types = 1);

namespace Tests\Unit\Logging;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Logging\LoggingSettings;
use SineMacula\Laravel\Sso\Logging\RedactedKeys;

/**
 * Unit tests for matching redacted keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RedactedKeys::class)]
final class RedactedKeysTest extends TestCase
{
    /**
     * Rows of `[key]`: a redacted key in the forms it may be written in.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMatchingKeys(): iterable
    {
        yield from [
            'as written'                  => ['client_secret'],
            'in mixed case'               => ['Client_SECRET'],
            'percent-encoded'             => ['client%5fsecret'],
            'percent-encoded upper case'  => ['client%5Fsecret'],
            'wholly percent-encoded'      => ['%63%6F%64%65'],
            'double-encoded'              => ['client%255Fsecret'],
            'encoded the most times read' => [self::encode('code', RedactedKeys::MAX_DECODES)],
            'plus-encoded'                => ['client+secret'],
            'a form array'                => ['client_secret[]'],
            'a nested form'               => ['user[password]'],
            'an encoded nested form'      => ['user%5Bpassword%5D'],
            'a deeper nested form'        => ['a[b][refresh_token]'],
            'namespaced'                  => ['ds:Signature'],
            'a configured key'            => ['X-Api-Key'],
            'a joined name'               => ['x+client_secret'],
            'a spaced name'               => ['private key'],
            'a spaced name in any case'   => ['SAML Response'],
            'a dotted path'               => ['credentials.password'],
            'a deeper dotted path'        => ['sso.oidc.client_secret'],
            'a slashed path'              => ['user/password'],
            'a header name'               => ['X-Client-Secret'],
            'a run of words within'       => ['the client secret value'],
        ];
    }

    /**
     * A redacted key matches in every form it may be written in.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideMatchingKeys')]
    public function testMatchesARedactedKey(string $key): void
    {
        self::assertTrue(self::keys()->matches($key));
    }

    /**
     * Rows of `[key]`: keys that only contain a redacted key, or none.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOtherKeys(): iterable
    {
        yield from [
            'a longer name'           => ['error_code'],
            'an encoded longer name'  => ['error%5Fcode'],
            'a plural'                => ['codes'],
            'a type'                  => ['token_type'],
            'one word containing one' => ['oidc.statecode'],
            'separate halves'         => ['private.pem key_id'],
            'a form of other parts'   => ['user[name]'],
            'a public reference'      => ['request_reference'],
            'an empty key'            => [''],
            'punctuation'             => ['[]:+%'],
            'a configured key absent' => ['api_key'],
        ];
    }

    /**
     * A key that only contains a redacted key, or holds none, does not match.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideOtherKeys')]
    public function testDoesNotMatchAnotherKey(string $key): void
    {
        self::assertFalse(self::keys()->matches($key));
    }

    /**
     * Rows of `[text before, key, matched]`: a key found in text.
     *
     * @return iterable<string, array{string, string, bool}>
     */
    public static function provideKeysInText(): iterable
    {
        yield from [
            'a key alone'                => ['', 'password', true],
            'a spaced name'              => ['the private ', 'key', true],
            'a spaced SAML name'         => ['bad SAML ', 'Response', true],
            'an encoded space'           => ['private%20', 'key', true],
            'a name run into a form key' => ['private ', 'key[0]', true],
            'an innocent key'            => ['the ', 'reason', false],
            'a redacted word before it'  => ['the code was ', 'reason', false],
            'a redacted key before it'   => ['code=[redacted] ', 'reason', false],
            'half of a name, apart'      => ['private, then ', 'key', false],
            'a name past the lookback'   => [str_repeat('x', 200) . ' private ', 'key', true],
            'a word cut by the lookback' => ['xsaml' . str_repeat(',', 123) . ' ', 'response', false],
        ];
    }

    /**
     * A key matches when the words running into it name a redacted key.
     *
     * @param  string  $before
     * @param  string  $key
     * @param  bool  $matched
     * @return void
     */
    #[DataProvider('provideKeysInText')]
    public function testMatchesAKeyNamedByTheWordsBeforeIt(string $before, string $key, bool $matched): void
    {
        self::assertSame($matched, self::keys()->matchesAfter($before, $key));
    }

    /**
     * A key still encoded after full decoding is treated as redacted.
     *
     * @return void
     */
    public function testMatchesAKeyEncodedPastReading(): void
    {
        self::assertTrue(self::keys()->matches(self::encode('reference', RedactedKeys::MAX_DECODES + 1)));
        self::assertFalse(self::keys()->matches(self::encode('reference', RedactedKeys::MAX_DECODES)));
    }

    /**
     * The keys, from the settings: the built-in ones and `x-api-key`.
     *
     * @return \SineMacula\Laravel\Sso\Logging\RedactedKeys
     */
    private static function keys(): RedactedKeys
    {
        return RedactedKeys::from(new LoggingSettings(new Repository(['sso' => ['logging' => ['redacted_keys' => ['x-api-key']]]])));
    }

    /**
     * The text percent-encoded `$times` times, every character the first time.
     *
     * @param  string  $text
     * @param  int  $times
     * @return string
     */
    private static function encode(string $text, int $times): string
    {
        for ($time = 0; $time < $times; $time++) {
            $text = $time === 0 ? implode('', array_map(static fn (string $char): string => sprintf('%%%02X', ord($char)), str_split($text))) : rawurlencode($text);
        }

        return $text;
    }
}
