<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\IdTokens;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens\ClaimTypes;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Base64Url;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for the exact type of every ID token claim the package reads.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClaimTypes::class)]
final class ClaimTypesTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var string A number too large for an integer. */
    private const string LARGE = '123456789012345678901234567890';

    /** @var int The instant the claims are issued at. */
    private const int NOW = 1900000000;

    /**
     * Rows of `[claims]`: claims laid over a valid token's, each with its type.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideTypedClaims(): iterable
    {
        yield from [
            'the required claims alone'     => [[]],
            'a subject of one byte'         => [['sub' => 'a']],
            'a subject under the cap'       => [['sub' => str_repeat('a', 1023)]],
            'a subject at the cap'          => [['sub' => str_repeat('a', 1024)]],
            'a subject with whitespace'     => [['sub' => " a\tb "]],
            'an empty issuer, judged later' => [['iss' => '']],
            'one audience in a list'        => [['aud' => ['client']]],
            'several audiences'             => [['aud' => ['client', 'other']]],
            'audiences of another case'     => [['aud' => ['client', 'CLIENT']]],
            'audiences of one number'       => [['aud' => ['1', '01', '1.0']]],
            'exp as a float'                => [['exp' => self::NOW + 300.5]],
            'iat as a float'                => [['iat' => self::NOW + 0.5]],
            'nbf as an integer'             => [['nbf' => self::NOW]],
            'nbf as a float'                => [['nbf' => self::NOW + 0.5]],
            'auth_time as an integer'       => [['auth_time' => self::NOW]],
            'auth_time as a float'          => [['auth_time' => self::NOW + 0.5]],
            'auth_time of zero'             => [['auth_time' => 0]],
            'azp a string'                  => [['azp' => 'client']],
            'azp empty, judged later'       => [['azp' => '']],
            'nonce a string'                => [['nonce' => 'n']],
            'nonce empty, judged later'     => [['nonce' => '']],
            'at_hash a string'              => [['at_hash' => 'h']],
            'at_hash empty, judged later'   => [['at_hash' => '']],
            'acr of one byte'               => [['acr' => 'a']],
            'acr under the cap'             => [['acr' => str_repeat('a', 1023)]],
            'acr at the cap'                => [['acr' => str_repeat('a', 1024)]],
            'sid of one byte'               => [['sid' => 'a']],
            'sid under the cap'             => [['sid' => str_repeat('a', 1023)]],
            'sid at the cap'                => [['sid' => str_repeat('a', 1024)]],
            'amr empty'                     => [['amr' => []]],
            'amr of one'                    => [['amr' => ['pwd']]],
            'amr repeating a method'        => [['amr' => ['pwd', 'pwd']]],
            'amr under the cap'             => [['amr' => array_fill(0, 31, 'pwd')]],
            'amr at the cap'                => [['amr' => array_fill(0, 32, 'pwd')]],
            'a method of one byte'          => [['amr' => ['a']]],
            'a method under the cap'        => [['amr' => [str_repeat('a', 254)]]],
            'a method at the cap'           => [['amr' => [str_repeat('a', 255)]]],
            'email a string'                => [['email' => 'a@example.test']],
            'email empty'                   => [['email' => '']],
            'email_verified true'           => [['email_verified' => true]],
            'email_verified false'          => [['email_verified' => false]],
            'email_verified the string'     => [['email_verified' => 'true']],
            'email_verified the string no'  => [['email_verified' => 'false']],
            'email_verified one'            => [['email_verified' => 1]],
            'email_verified null'           => [['email_verified' => null]],
            'email_verified an object'      => [['email_verified' => ['a' => true]]],
            'email_verified a list'         => [['email_verified' => [true]]],
            'a claim the package ignores'   => [['groups' => ['a', 1, null]]],
            'a null the package ignores'    => [['locale' => null]],
        ];
    }

    /**
     * Claims of their types pass.
     *
     * @param  array<string, mixed>  $claims
     * @return void
     */
    #[DataProvider('provideTypedClaims')]
    public function testClaimsOfTheirTypesPass(array $claims): void
    {
        self::assertTrue(ClaimTypes::areTyped([...self::valid(), ...$claims]));
    }

    /**
     * Rows of `[claim, value]`: a claim of the wrong type or length.
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideWrongClaims(): iterable
    {
        yield from self::rows('iss', ['an array' => ['https://op.example.test'], 'a number' => 1, 'a boolean' => true, 'null' => null]);
        yield from self::rows('sub', ['an integer' => 1, 'empty' => '', '1025 bytes' => str_repeat('a', 1025), 'an array' => ['a'], 'a boolean' => true, 'null' => null]);
        yield from self::rows('aud', [
            'an object'          => ['client' => 'client'],
            'a keyed list'       => [1 => 'client'],
            'a number'           => 1,
            'an empty list'      => [],
            'a list of a number' => ['client', 1],
            'a list of a null'   => ['client', null],
            'a nested list'      => ['client', ['client']],
            'an empty string'    => '',
            'an empty entry'     => ['client', ''],
            'a repeated entry'   => ['client', 'client'],
            'a repeat apart'     => ['client', 'other', 'client'],
            'a boolean'          => true,
            'null'               => null,
        ]);

        foreach (['exp', 'iat', 'nbf', 'auth_time'] as $claim) {
            yield from self::rows($claim, [
                'a string'          => '1900000000',
                'a boolean'         => true,
                'an array'          => [self::NOW],
                'null'              => null,
                'infinity'          => INF,
                'negative infinity' => -INF,
                'not a number'      => NAN,
            ]);
        }

        foreach (['azp', 'nonce', 'at_hash', 'email'] as $claim) {
            yield from self::rows($claim, ['an array' => ['a'], 'a number' => 1, 'a boolean' => true, 'null' => null]);
        }

        foreach (['acr', 'sid'] as $claim) {
            yield from self::rows($claim, ['empty' => '', '1025 bytes' => str_repeat('a', 1025), 'a number' => 1, 'an array' => ['a'], 'null' => null]);
        }

        yield from self::rows('amr', [
            'a string'         => 'pwd',
            '33 entries'       => array_fill(0, 33, 'pwd'),
            'an empty entry'   => ['pwd', ''],
            'a 256-byte entry' => [str_repeat('a', 256)],
            'a number entry'   => ['pwd', 1],
            'a keyed list'     => ['first' => 'pwd'],
            'a number'         => 1,
            'null'             => null,
        ]);
    }

    /**
     * A claim of the wrong type or length refuses the token, whichever it is.
     *
     * @param  string  $claim
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideWrongClaims')]
    public function testAClaimOfTheWrongTypeIsRefused(string $claim, mixed $value): void
    {
        self::assertFalse(ClaimTypes::areTyped([...self::valid(), $claim => $value]));
    }

    /**
     * Rows of `[claim]`: each claim a token cannot go without.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRequiredClaims(): iterable
    {
        foreach (['iss', 'sub', 'aud', 'exp', 'iat'] as $claim) {
            yield $claim => [$claim];
        }
    }

    /**
     * A required claim missing refuses the token.
     *
     * @param  string  $claim
     * @return void
     */
    #[DataProvider('provideRequiredClaims')]
    public function testARequiredClaimMissingIsRefused(string $claim): void
    {
        self::assertFalse(ClaimTypes::areTyped(array_diff_key(self::valid(), [$claim => true])));
    }

    /**
     * Rows of `[payload, typed]`: a payload as its JSON text, which a PHP array
     * or the digits of a number would not tell apart.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function providePayloads(): iterable
    {
        $base   = '"iss":"i","sub":"s","exp":1900000300,"iat":1900000000';
        $slash  = chr(92);
        $times  = '"exp":1900000300,"iat":1900000000';
        $digits = '"' . self::LARGE . '"';

        yield from [
            'aud a string'             => ['{' . $base . ',"aud":"client"}', true],
            'aud a list'               => ['{' . $base . ',"aud":["client"]}', true],
            'aud an object of a list'  => ['{' . $base . ',"aud":{"0":"client"}}', false],
            'aud an object'            => ['{' . $base . ',"aud":{"client":"client"}}', false],
            'aud an empty object'      => ['{' . $base . ',"aud":{}}', false],
            'amr a list'               => ['{' . $base . ',"aud":"client","amr":["pwd"]}', true],
            'amr an object of a list'  => ['{' . $base . ',"aud":"client","amr":{"0":"pwd"}}', false],
            'amr an empty object'      => ['{' . $base . ',"aud":"client","amr":{}}', false],
            'exp too large to be held' => ['{"iss":"i","sub":"s","aud":"client","iat":1900000000,"exp":1e999}', false],
            'exp digits past an int'   => ['{"iss":"i","sub":"s","aud":"client","iat":1900000000,"exp":99999999999999999999999}', false],
            'a name no object holds'   => ['{' . $base . ',"aud":"client","' . $slash . 'u0000x":1}', false],
            'an object elsewhere'      => ['{' . $base . ',"aud":"client","address":{"0":"a"}}', true],
            'iss as a large number'    => ['{"iss":' . self::LARGE . ',"sub":"s","aud":"client","exp":1900000300,"iat":1900000000}', false],
            'sub as a large number'    => ['{"iss":"i","sub":' . self::LARGE . ',"aud":"client","exp":1900000300,"iat":1900000000}', false],
            'aud as a large number'    => ['{' . $base . ',"aud":' . self::LARGE . '}', false],
            'an aud item as one'       => ['{' . $base . ',"aud":["client",' . self::LARGE . ']}', false],
            'azp as a large number'    => ['{' . $base . ',"aud":"client","azp":' . self::LARGE . '}', false],
            'nonce as a large number'  => ['{' . $base . ',"aud":"client","nonce":' . self::LARGE . '}', false],
            'at_hash as a large one'   => ['{' . $base . ',"aud":"client","at_hash":' . self::LARGE . '}', false],
            'email as a large number'  => ['{' . $base . ',"aud":"client","email":' . self::LARGE . '}', false],
            'acr as a large number'    => ['{' . $base . ',"aud":"client","acr":' . self::LARGE . '}', false],
            'sid as a large number'    => ['{' . $base . ',"aud":"client","sid":' . self::LARGE . '}', false],
            'an amr item as one'       => ['{' . $base . ',"aud":"client","amr":["pwd",' . self::LARGE . ']}', false],
            'the digits as strings'    => ['{"iss":' . $digits . ',"sub":' . $digits . ',"aud":[' . $digits . '],' . $times . ',"amr":[' . $digits . ']}', true],
            'a large number elsewhere' => ['{' . $base . ',"aud":"client","employee":' . self::LARGE . '}', true],
        ];
    }

    /**
     * A token's refusal reads its JSON: an object is never read as a list, and
     * the reason is `id_token_invalid`.
     *
     * @param  string  $payload
     * @param  bool  $typed
     * @return void
     */
    #[DataProvider('providePayloads')]
    public function testTheRefusalReadsTheTokensJson(string $payload, bool $typed): void
    {
        $token = CompactToken::parse(Base64Url::encode('{"alg":"RS256"}') . '.' . Base64Url::encode($payload) . '.' . Base64Url::encode('signature'), 16384);

        self::assertNotNull($token);
        self::assertSame($typed ? null : FailureReason::ID_TOKEN_INVALID, ClaimTypes::refusal($token));
    }

    /**
     * The rows of a claim's wrong values, each named for the claim and value.
     *
     * @param  string  $claim
     * @param  array<string, mixed>  $values
     * @return array<string, array{0: string, 1: mixed}>
     */
    private static function rows(string $claim, array $values): array
    {
        $rows = [];

        foreach ($values as $name => $value) {
            $rows["{$claim} {$name}"] = [$claim, $value];
        }

        return $rows;
    }

    /**
     * The required claims, each of its type.
     *
     * @return array<string, mixed>
     */
    private static function valid(): array
    {
        return ['iss' => 'https://op.example.test', 'sub' => 'person', 'aud' => 'client', 'exp' => self::NOW + 300, 'iat' => self::NOW];
    }
}
