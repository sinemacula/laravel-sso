<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Jose;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for reading a compact JWS (RFC 7515 §7.1, SSO-7.3): three
 * canonical segments within the cap, a header and payload that are each one
 * JSON object without a repeated member, a named algorithm and a non-empty
 * signature, with `crit`, `b64`, `enc` and `zip` refused and `kid` and `typ`
 * typed; and nothing of it shown in a dump or serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompactToken::class)]
final class CompactTokenTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var string A signature segment. */
    private const string SIGNATURE = 'c2lnbmF0dXJl';

    /**
     * A token is read: its header, algorithm, `kid`, claims and the token as
     * given.
     *
     * @return void
     */
    public function testATokenIsRead(): void
    {
        $compact = self::compact('{"alg":"RS256","kid":"k1","typ":"JWT"}', '{"sub":"a","exp":1}');
        $token   = CompactToken::parse($compact, 16384);

        self::assertNotNull($token);
        self::assertSame(['alg' => 'RS256', 'kid' => 'k1', 'typ' => 'JWT'], $token->header());
        self::assertSame('RS256', $token->algorithm());
        self::assertSame('k1', $token->keyId());
        self::assertSame(['sub' => 'a', 'exp' => 1], $token->claims());
        self::assertSame($compact, $token->compact());
    }

    /**
     * A token without a `kid` has none.
     *
     * @return void
     */
    public function testATokenWithoutAKidHasNone(): void
    {
        self::assertNull(CompactToken::parse(self::compact('{"alg":"RS256"}', '{}'), 16384)?->keyId());
    }

    /**
     * A token of exactly the cap is read; one byte more is refused, and an
     * empty one is never read.
     *
     * @return void
     */
    public function testTheCapIsHeldAtItsBoundary(): void
    {
        $compact = self::compact('{"alg":"RS256"}', '{"sub":"a"}');
        $length  = strlen($compact);

        self::assertNotNull(CompactToken::parse($compact, $length));
        self::assertNull(CompactToken::parse($compact, $length - 1));
        self::assertNull(CompactToken::parse('', 16384));
    }

    /**
     * Rows of `[token]`: what is never read.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusals(): iterable
    {
        $header = self::segment('{"alg":"RS256","kid":"k1"}');
        $claims = self::segment('{"sub":"a"}');

        yield from [
            'two segments'             => [$header . '.' . $claims],
            'four segments'            => [$header . '.' . $claims . '.' . self::SIGNATURE . '.x'],
            'a JWE'                    => [$header . '.a.b.c.d'],
            'an empty signature'       => [$header . '.' . $claims . '.'],
            'a padded signature'       => [$header . '.' . $claims . '.c2lnbmF0dXJlMQ=='],
            'a padded header'          => [base64_encode('{"alg":"RS256"} ') . '.' . $claims . '.' . self::SIGNATURE],
            'an empty header'          => ['.' . $claims . '.' . self::SIGNATURE],
            'an empty payload'         => [$header . '..' . self::SIGNATURE],
            'a header of a list'       => [self::compact('["alg"]', '{}')],
            'a payload of a list'      => [self::compact('{"alg":"RS256"}', '["sub"]')],
            'a payload of a string'    => [self::compact('{"alg":"RS256"}', '"sub"')],
            'a repeated header member' => [self::compact('{"alg":"RS256","alg":"none"}', '{}')],
            'a repeated claim'         => [self::compact('{"alg":"RS256"}', '{"sub":"a","sub":"b"}')],
            'a repeated claim, nested' => [self::compact('{"alg":"RS256"}', '{"a":{"b":1,"b":2}}')],
            'no alg'                   => [self::compact('{"kid":"k1"}', '{}')],
            'an empty alg'             => [self::compact('{"alg":""}', '{}')],
            'alg not a string'         => [self::compact('{"alg":256}', '{}')],
            'crit'                     => [self::compact('{"alg":"RS256","crit":["exp"]}', '{}')],
            'b64'                      => [self::compact('{"alg":"RS256","b64":true}', '{}')],
            'enc'                      => [self::compact('{"alg":"RS256","enc":"A256GCM"}', '{}')],
            'zip'                      => [self::compact('{"alg":"RS256","zip":"DEF"}', '{}')],
            'kid empty'                => [self::compact('{"alg":"RS256","kid":""}', '{}')],
            'kid a number'             => [self::compact('{"alg":"RS256","kid":0}', '{}')],
            'kid null'                 => [self::compact('{"alg":"RS256","kid":null}', '{}')],
            'kid a list'               => [self::compact('{"alg":"RS256","kid":["k1"]}', '{}')],
            'typ a number'             => [self::compact('{"alg":"RS256","typ":1}', '{}')],
            'typ null'                 => [self::compact('{"alg":"RS256","typ":null}', '{}')],
            'alg too large a number'   => [self::compact('{"alg":99999999999999999999}', '{}')],
            'kid too large a number'   => [self::compact('{"alg":"RS256","kid":99999999999999999999}', '{}')],
            'typ too large a number'   => [self::compact('{"alg":"RS256","typ":99999999999999999999}', '{}')],
        ];
    }

    /**
     * Anything but a compact JWS the package reads is refused.
     *
     * @param  string  $token
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testAnythingElseIsRefused(string $token): void
    {
        self::assertNull(CompactToken::parse($token, 16384));
    }

    /**
     * The headers whose presence refuses a token are these.
     *
     * @return void
     */
    public function testTheRefusedHeadersAreThese(): void
    {
        self::assertSame(['crit', 'b64', 'enc', 'zip'], CompactToken::REFUSED_HEADERS);
    }

    /**
     * `jku`, `x5u`, `jwk` and `x5c` neither refuse a token nor change what it
     * is read as.
     *
     * @return void
     */
    public function testKeysOfferedInTheHeaderAreIgnored(): void
    {
        $token = CompactToken::parse(self::compact('{"alg":"RS256","jku":"https://a.test","x5u":"https://b.test","jwk":{},"x5c":["MII"]}', '{}'), 16384);

        self::assertSame(['RS256', null], [$token?->algorithm(), $token?->keyId()]);
    }

    /**
     * A header's digits as a string are its `kid`, and an unknown member that
     * is too large a number is no refusal here, since only the signature check
     * reads it.
     *
     * @return void
     */
    public function testAHeaderIsReadAsJsonWroteIt(): void
    {
        $token = CompactToken::parse(self::compact('{"alg":"RS256","kid":"99999999999999999999","x":99999999999999999999}', '{}'), 16384);

        self::assertSame('99999999999999999999', $token?->keyId());
        self::assertSame(['alg' => 'RS256', 'kid' => '99999999999999999999', 'x' => '99999999999999999999'], $token->header());
    }

    /**
     * The claims keep a number's digits, so a time claim refuses it; the
     * members, what a token that passed hands on, keep it a number; and the
     * payload is its JSON text.
     *
     * @return void
     */
    public function testTheClaimsTheMembersAndThePayload(): void
    {
        $payload = '{"exp":99999999999999999999,"sub":"a"}';
        $token   = CompactToken::parse(self::compact('{"alg":"RS256"}', $payload), 16384);

        self::assertSame(['exp' => '99999999999999999999', 'sub' => 'a'], $token?->claims());
        self::assertSame(['exp' => 1.0E+20, 'sub' => 'a'], $token->members());
        self::assertSame($payload, $token->payload());
    }

    /**
     * A dump shows a known algorithm and whether a `kid` is present, never the
     * token, its `kid` or a claim, and JSON encoding shows the same.
     *
     * @return void
     */
    public function testADumpShowsNothingOfTheToken(): void
    {
        $token = CompactToken::parse(self::compact('{"alg":"RS256","kid":"secret-kid"}', '{"sub":"secret-subject"}'), 16384);
        $shown = ['alg' => 'RS256', 'kid' => '[present]', 'token' => '[redacted]'];

        self::assertSame($shown, $token?->__debugInfo());
        self::assertSame($shown, $token->jsonSerialize());
        self::assertSame(['alg' => 'RS256', 'kid' => null, 'token' => '[redacted]'], CompactToken::parse(self::compact('{"alg":"RS256"}', '{}'), 16384)?->__debugInfo());
    }

    /**
     * Rows of `[algorithm, shown]`: every algorithm the package knows shown
     * verbatim, and anything else, an algorithm it refuses included, never.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideAlgorithmsShown(): iterable
    {
        foreach (['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'] as $algorithm) {
            yield $algorithm => [$algorithm, $algorithm];
        }

        yield from [
            'none'             => ['none', '[unknown]'],
            'an HMAC'          => ['HS256', '[unknown]'],
            'another case'     => ['rs256', '[unknown]'],
            'a sensitive text' => ['secret-algorithm', '[unknown]'],
        ];
    }

    /**
     * The algorithm is shown verbatim only once it is one the package knows,
     * while `algorithm()` still answers what the header holds.
     *
     * @param  string  $algorithm
     * @param  string  $shown
     * @return void
     */
    #[DataProvider('provideAlgorithmsShown')]
    public function testADumpShowsOnlyAKnownAlgorithm(string $algorithm, string $shown): void
    {
        $token = CompactToken::parse(self::compact((string) json_encode(['alg' => $algorithm]), '{}'), 16384);

        self::assertSame($shown, $token?->__debugInfo()['alg']);
        self::assertSame($shown, $token->jsonSerialize()['alg']);
        self::assertSame($algorithm, $token->algorithm());
    }

    /**
     * Rows of `[what shows the token]`: every way a value leaves the object.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken): string}>
     */
    public static function provideChannels(): iterable
    {
        yield from [
            'json_encode' => [static fn (CompactToken $token): string => (string) json_encode($token)],
            'var_dump'    => [static function (CompactToken $token): string {

                ob_start();
                var_dump($token); // @phpcs:ignore

                return (string) ob_get_clean();
            }],
            'print_r'        => [static fn (CompactToken $token): string => print_r($token, true)],
            'var_export'     => [static fn (CompactToken $token): string => var_export($token, true)],
            'an array cast'  => [static fn (CompactToken $token): string => var_export((array) $token, true)],
            'an array print' => [static fn (CompactToken $token): string => print_r((array) $token, true)],
            'VarDumper'      => [static fn (CompactToken $token): string => (string) (new CliDumper)->dump((new VarCloner)->cloneVar($token), true)],
        ];
    }

    /**
     * No way of showing a token shows a marker of its header or its claims: an
     * algorithm the package does not know, a `kid`, a `typ`, or an extension.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken): string  $show
     * @return void
     */
    #[DataProvider('provideChannels')]
    public function testNoChannelShowsTheHeaderOrTheClaims(\Closure $show): void
    {
        $header = '{"alg":"marker-alg","kid":"marker-kid","typ":"marker-typ","marker-name":"marker-value"}';
        $token  = CompactToken::parse(self::compact($header, '{"sub":"marker-subject"}'), 16384);

        self::assertNotNull($token);

        $shown = $show($token);

        self::assertStringNotContainsString('marker', $shown);
        self::assertStringNotContainsString(self::segment($header), $shown);
    }

    /**
     * What the marker test reads shows the token itself, so its silence is the
     * redaction's rather than a channel that shows nothing.
     *
     * @return void
     */
    public function testEachChannelShowsTheToken(): void
    {
        $token = CompactToken::parse(self::compact('{"alg":"RS256"}', '{}'), 16384);

        self::assertNotNull($token);
        self::assertSame('{"alg":"RS256","kid":null,"token":"[redacted]"}', json_encode($token));
        self::assertStringContainsString('[redacted]', print_r($token, true));
        self::assertStringContainsString(\SensitiveParameterValue::class, var_export($token, true));
        self::assertStringContainsString(\SensitiveParameterValue::class, var_export((array) $token, true));
    }

    /**
     * A token refuses to be serialised.
     *
     * @return void
     */
    public function testATokenIsNeverSerialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A provider token cannot be serialised.'));

        serialize(CompactToken::parse(self::compact('{"alg":"RS256"}', '{}'), 16384));
    }

    /**
     * A token refuses to be unserialised.
     *
     * @return void
     */
    public function testATokenIsNeverUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A provider token cannot be unserialised.'));

        unserialize('O:' . strlen(CompactToken::class) . ':"' . CompactToken::class . '":0:{}');
    }

    /**
     * A token of the header and payload JSON, with a signature.
     *
     * @param  string  $header
     * @param  string  $payload
     * @return string
     */
    private static function compact(string $header, string $payload): string
    {
        return self::segment($header) . '.' . self::segment($payload) . '.' . self::SIGNATURE;
    }

    /**
     * The text as unpadded base64url.
     *
     * @param  string  $text
     * @return string
     */
    private static function segment(string $text): string
    {
        return rtrim(strtr(base64_encode($text), '+/', '-_'), '=');
    }
}
