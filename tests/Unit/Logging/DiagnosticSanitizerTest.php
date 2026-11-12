<?php

declare(strict_types = 1);

namespace Tests\Unit\Logging;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Logging\DiagnosticSanitizer;
use SineMacula\Laravel\Sso\Logging\KeyedValues;
use SineMacula\Laravel\Sso\Logging\LoggingSettings;
use SineMacula\Laravel\Sso\Logging\RedactedKeys;

/**
 * Unit tests for the diagnostic sanitiser; secret fixtures are assembled from
 * parts so secret scanners ignore them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiagnosticSanitizer::class)]
#[CoversClass(KeyedValues::class)]
#[CoversClass(RedactedKeys::class)]
final class DiagnosticSanitizerTest extends TestCase
{
    /** @var string The encoded header of a JWS signed with RS256. */
    private const string HEADER = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0';

    /** @var string The encoded payload of a JWS. */
    private const string PAYLOAD = 'eyJzdWIiOiIyNDgyODk3NjEwMDEiLCJub25jZSI6Im4tMFM2In0';

    /** @var string A JWS: a header, a payload and a signature. */
    private const string JWT = self::HEADER . '.' . self::PAYLOAD . '.c2lnbmF0dXJlLWJ5dGVz';

    /** @var string An ordinary diagnostic, with nothing to sanitise. */
    private const string SENTENCE = 'The identity provider refused the request: error=access_denied, the user cancelled the sign-in at 12:00 (attempt 2 of 3).';

    /** @var string Sixty characters of ordinary text: twelve words of five. */
    private const string SIXTY = 'word word word word word word word word word word word word ';

    /** @var string The label of a private key's PEM block. */
    private const string PRIVATE_KEY = 'PRIVATE KEY';

    /**
     * Rows of `[text, sanitised]`: tabs and breaks become a space, others go.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideControls(): iterable
    {
        yield from [
            'a line feed'           => ["one\ntwo", 'one two'],
            'a carriage return'     => ["one\rtwo", 'one two'],
            'a CRLF'                => ["one\r\ntwo", 'one two'],
            'a tab'                 => ["one\ttwo", 'one two'],
            'a vertical tab'        => ["one\x0Btwo", 'one two'],
            'a form feed'           => ["one\ftwo", 'one two'],
            'a forged log line'     => ["refused\n[2026-11-01 00:00:00] production.INFO: signed in", 'refused [2026-11-01 00:00:00] production.INFO: signed in'],
            'a NUL'                 => ["one\x00two", 'onetwo'],
            'a bell'                => ["one\x07two", 'onetwo'],
            'an escape sequence'    => ["\x1B[31mred\x1B[0m", '[31mred[0m'],
            'the last C0 control'   => ["one\x1Ftwo", 'onetwo'],
            'DEL'                   => ["one\x7Ftwo", 'onetwo'],
            'the first C1 control'  => ["one\u{0080}two", 'onetwo'],
            'a next line'           => ["one\u{0085}two", 'onetwo'],
            'a CSI'                 => ["one\u{009B}two", 'onetwo'],
            'the last C1 control'   => ["one\u{009F}two", 'onetwo'],
            'an arabic letter mark' => ["one\u{061C}two", 'onetwo'],
            'a left-to-right mark'  => ["one\u{200E}two", 'onetwo'],
            'a right-to-left mark'  => ["one\u{200F}two", 'onetwo'],
            'a line separator'      => ["one\u{2028}two", 'one two'],
            'a no-break space'      => ["one\u{00A0}two", 'one two'],
            'leading and trailing'  => ["\n\t one two \r\n", 'one two'],
            'a run of whitespace'   => ["one \t\n  two", 'one two'],
        ];

        foreach ([0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069] as $codepoint) {
            yield sprintf('bidi control U+%04X', $codepoint) => ['user' . mb_chr($codepoint, 'UTF-8') . 'name', 'username'];
        }
    }

    /**
     * Controls are removed and whitespace collapses, so no log line is forged.
     *
     * @param  string  $text
     * @param  string  $sanitized
     * @return void
     */
    #[DataProvider('provideControls')]
    public function testRemovesControlCharacters(string $text, string $sanitized): void
    {
        self::assertSame($sanitized, self::sanitizer()->sanitize($text));
    }

    /**
     * Rows of `[text, sanitised]`: invalid UTF-8 and what it is scrubbed to.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideInvalidUtf8(): iterable
    {
        yield from [
            'a truncated sequence'   => ["caf\xC3", 'caf?'],
            'bytes that never start' => ["\xFF\xFEok", '??ok'],
            'an overlong encoding'   => ["\xC0\xAFx", '??x'],
            'a cut three-byte form'  => ["a\xE2\x80b", 'a?b'],
        ];
    }

    /**
     * Invalid UTF-8 is scrubbed, so what is logged is always valid UTF-8.
     *
     * @param  string  $text
     * @param  string  $sanitized
     * @return void
     */
    #[DataProvider('provideInvalidUtf8')]
    public function testScrubsInvalidUtf8(string $text, string $sanitized): void
    {
        $result = self::sanitizer()->sanitize($text);

        self::assertSame($sanitized, $result);
        self::assertTrue(mb_check_encoding($result, 'UTF-8'));
    }

    /**
     * Rows of `[text, sanitised]`: each kind of secret and its redaction.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideSecrets(): iterable
    {
        $base64    = base64_encode(str_repeat("\x9B\xF0\x3E", 20));
        $base64url = rtrim(strtr($base64, '+/', '-_'), '=');
        $jwe       = implode('.', ['eyJhbGciOiJSU0EtT0FFUCJ9', 'a2V5', 'aXY', 'Y2lwaGVy', 'dGFn']);
        $unsigned  = implode('.', ['eyJhbGciOiJub25lIn0', 'eyJzdWIiOiIxIn0', '']);

        yield from [
            'a JWT'                   => ['token ' . self::JWT . ' rejected', 'token [redacted] rejected'],
            'a JWE'                   => ['token ' . $jwe . ' rejected', 'token [redacted] rejected'],
            'a JWT with no signature' => [$unsigned, '[redacted]'],
            'a Bearer credential'     => ['sent Bearer mF_9.B5f-4.1JqM end', 'sent Bearer [redacted] end'],
            'a lower-case bearer'     => ['retry with bearer mF_9.B5f-4.1JqM', 'retry with bearer [redacted]'],
            'a Basic credential'      => ['sent Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW', 'sent Basic [redacted]'],
            'a code'                  => ['code=abc', 'code=[redacted]'],
            'a code with spaces'      => ['code = abc', 'code = [redacted]'],
            'code and state in a URL' => [
                'https://app.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj&iss=https://idp.example.com',
                'https://app.example.com/cb?code=[redacted]&state=[redacted]&iss=https://idp.example.com',
            ],
            'a code in a fragment' => ['https://app.example.com/done#code=abc', 'https://app.example.com/done#code=[redacted]'],
            'a padded value'       => ['SAMLResponse=PHNhbWxw%3D&RelayState=abc', 'SAMLResponse=[redacted]&RelayState=[redacted]'],
            'a JSON access token'  => ['"access_token":"x"', '"access_token":"[redacted]"'],
            'a JSON body'          => [
                '{"error":"invalid_grant","refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA","expires_in":3600}',
                '{"error":"invalid_grant","refresh_token":"[redacted]","expires_in":3600}',
            ],
            'a JSON member with spaces' => ['{"id_token" : "abc"}', '{"id_token" : "[redacted]"}'],
            'a JSON escaped quote'      => ['{"password":"a\"b","user":"bob"}', '{"password":"[redacted]","user":"bob"}'],
            'a JSON number'             => ['{"code": 123456}', '{"code": "[redacted]"}'],
            'a JSON boolean'            => ['{"nonce":true}', '{"nonce":"[redacted]"}'],
            'escaped JSON'              => ['body {\"id_token\":\"abc\",\"error\":\"bad\"}', 'body {\"id_token\":\"[redacted]\",\"error\":\"bad\"}'],
            'a long base64 run'         => ['response ' . $base64 . ' rejected', 'response [redacted] rejected'],
            'a long base64url run'      => ['code ' . $base64url . ' rejected', 'code [redacted] rejected'],
            'forty characters'          => ['ref ' . str_repeat('abcd', 10) . ' end', 'ref [redacted] end'],
            'a SAML assertion'          => [
                'status <saml:Assertion ID="_a1" Version="2.0"><saml:Subject><saml:NameID>bob@example.com</saml:NameID></saml:Subject></saml:Assertion> end',
                'status [redacted] end',
            ],
            'an unprefixed assertion'  => ['<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">bob</Assertion>', '[redacted]'],
            'an encrypted assertion'   => ['<saml:EncryptedAssertion><xenc:EncryptedData>abc</xenc:EncryptedData></saml:EncryptedAssertion> end', '[redacted] end'],
            'an assertion cut short'   => ['status <saml:Assertion ID="_a1"><saml:NameID>bob@example.com', 'status [redacted]'],
            'a self-closing assertion' => ['<saml:Assertion ID="_a1"/> end', '[redacted] end'],
            'a signature value'        => ['<ds:SignatureValue>abc</ds:SignatureValue>', '[redacted]'],
            'a certificate'            => ['<ds:X509Certificate>MIIC</ds:X509Certificate> end', '[redacted] end'],
            'a PEM'                    => [sprintf("-----BEGIN %s-----\nMIIE\n-----END %s----- loaded", self::PRIVATE_KEY, self::PRIVATE_KEY), '[redacted] loaded'],
            'a certificate PEM'        => ["key -----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", 'key [redacted]'],
            'a PEM cut short'          => [sprintf("key -----BEGIN RSA %s-----\nMIIE", self::PRIVATE_KEY), 'key [redacted]'],
            'an element by key'        => [
                '<samlp:RelayState>xyz</samlp:RelayState> <saml:Issuer>idp</saml:Issuer>',
                '<samlp:RelayState>[redacted]</samlp:RelayState> <saml:Issuer>idp</saml:Issuer>',
            ],
            'an element with attributes'  => ['<code lang="x">abc</code>', '<code lang="x">[redacted]</code>'],
            'an attribute by key'         => ['<samlp:Response ID="_r1" State="abc" InResponseTo="_q1">', '<samlp:Response ID="_r1" State="[redacted]" InResponseTo="_q1">'],
            'a prefixed attribute by key' => ['<x ds:Signature="abc">', '<x ds:Signature="[redacted]">'],
            'a single-quoted pair'        => ['client_secret = \'s3cr3t\' end', 'client_secret = \'[redacted]\' end'],
            'keys in any form'            => [
                'Client-Secret=a CLIENT_SECRET=b clientSecret=c client.secret=d',
                'Client-Secret=[redacted] CLIENT_SECRET=[redacted] clientSecret=[redacted] client.secret=[redacted]',
            ],
        ];
    }

    /**
     * Each secret is replaced with `[redacted]`, and what is around it kept.
     *
     * @param  string  $text
     * @param  string  $sanitized
     * @return void
     */
    #[DataProvider('provideSecrets')]
    public function testRedactsSecrets(string $text, string $sanitized): void
    {
        self::assertSame($sanitized, self::sanitizer()->sanitize($text));
    }

    /**
     * Rows of `[text, sanitised]`: awkward values and keys under redaction.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideWholeValues(): iterable
    {
        yield from self::providePairValues();
        yield from self::provideJsonValues();
        yield from self::provideElementValues();
    }

    /**
     * The whole value under a redacted key is replaced, however it is written.
     *
     * @param  string  $text
     * @param  string  $sanitized
     * @return void
     */
    #[DataProvider('provideWholeValues')]
    public function testRedactsWholeValues(string $text, string $sanitized): void
    {
        self::assertSame($sanitized, self::sanitizer()->sanitize($text));
    }

    /**
     * Rows of `[text]`: text that only looks like a secret, kept as it is.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideLookalikes(): iterable
    {
        yield from [
            'a key containing a redacted key' => ['error_code=E1 statecode=x codes=1'],
            'a JSON key containing one'       => ['{"error_code":"E1","token_type":"Bearer"}'],
            'an element containing one'       => ['<saml:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>'],
            'an assertion consumer service'   => ['<md:AssertionConsumerService Location="https://sp.example.com/acs"/>'],
            'thirty-nine characters'          => ['ref ' . str_repeat('abc', 13) . ' end'],
            'empty values'                    => ['https://app.example.com/cb?code=&state=&nonce='],
            'a UUID reference'                => ['reference=01929e5c-7b1d-7cc4-9a3e-5f0c2b8d4e61'],
            'an encoded harmless URL'         => ['next=%2Fhome%3Ftab%3Dprofile 100%25 done'],
            'an encoded key containing one'   => ['error%5Fcode=E1&user[name]=bob'],
            'JSON values of every type'       => ['{"error":"bad","token_type":["Bearer"],"tokens":{"a":1},"n":-1.5,"ok":false,"x":null}'],
            'an element with children'        => ['<samlp:StatusCode><x>a</x></samlp:StatusCode>'],
            'JSON keys with no value'         => ['{"code": , "state": } {"nonce":'],
            'an empty element'                => ['<code></code> <state/>'],
            'a redacted word before a pair'   => ['the state was lost, reason=expired'],
            'a redacted value before a pair'  => ['code=[redacted] reason=expired'],
            'colons in prose'                 => ['error: invalid_request at 12:00:05, see https://idp.example.com/help'],
            'a JSON key with no value'        => ['{"password": }'],
        ];
    }

    /**
     * Text that only looks like a secret is kept.
     *
     * @param  string  $text
     * @return void
     */
    #[DataProvider('provideLookalikes')]
    public function testKeepsLookalikes(string $text): void
    {
        self::assertSame($text, self::sanitizer()->sanitize($text));
    }

    /**
     * A key in `sso.logging.redacted_keys` is redacted in every form.
     *
     * @return void
     */
    public function testRedactsAConfiguredKey(): void
    {
        $text = 'X-Api-Key=abc x_api_key="def" {"xApiKey":"ghi"} ApiKey=jkl code=mno';

        self::assertSame(
            'X-Api-Key=[redacted] x_api_key="[redacted]" {"xApiKey":"[redacted]"} ApiKey=jkl code=[redacted]',
            self::sanitizer(['redacted_keys' => ['x-api-key']])->sanitize($text),
        );

        self::assertSame('X-Api-Key=abc x_api_key="def" {"xApiKey":"ghi"} ApiKey=jkl code=[redacted]', self::sanitizer()->sanitize($text));
    }

    /**
     * Rows of `[text, sanitised]`: text around a cap of 64 characters.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideCapped(): iterable
    {
        yield from [
            'one under the cap'        => [self::SIXTY . 'fou', self::SIXTY . 'fou'],
            'exactly the cap'          => [self::SIXTY . 'four', self::SIXTY . 'four'],
            'one past the cap'         => [self::SIXTY . 'fives', self::SIXTY . 'fiv…'],
            'far past the cap'         => [str_repeat(self::SIXTY, 10), self::SIXTY . 'wor…'],
            'multibyte at the cap'     => [str_repeat('é', 64), str_repeat('é', 64)],
            'multibyte past the cap'   => [str_repeat('é', 65), str_repeat('é', 63) . '…'],
            'counted after collapsing' => [str_replace(' ', "  \n", self::SIXTY) . 'four', self::SIXTY . 'four'],
        ];
    }

    /**
     * Text is capped in characters, ending in an ellipsis when cut.
     *
     * @param  string  $text
     * @param  string  $sanitized
     * @return void
     */
    #[DataProvider('provideCapped')]
    public function testCapsTheLength(string $text, string $sanitized): void
    {
        $result = self::sanitizer(['max_diagnostic_length' => 64])->sanitize($text);

        self::assertSame($sanitized, $result);
        self::assertLessThanOrEqual(64, mb_strlen($result, 'UTF-8'));
    }

    /**
     * The cap defaults to 512 characters.
     *
     * @return void
     */
    public function testTheCapDefaultsTo512Characters(): void
    {
        $text = str_repeat('word ', 200);

        self::assertSame(512, mb_strlen(self::sanitizer()->sanitize($text), 'UTF-8'));
        self::assertSame(511, mb_strlen(self::sanitizer()->sanitize(substr($text, 0, 511)), 'UTF-8'));
    }

    /**
     * Redaction runs before the cap, so no secret is left half there.
     *
     * @return void
     */
    public function testRedactsBeforeCapping(): void
    {
        $result = self::sanitizer(['max_diagnostic_length' => 64])->sanitize(self::SIXTY . self::JWT);

        self::assertSame(self::SIXTY . '[re…', $result);
        self::assertStringNotContainsString('eyJ', $result);
    }

    /**
     * Ordinary text, with nothing to sanitise, is untouched.
     *
     * @return void
     */
    public function testLeavesAnOrdinarySentenceUntouched(): void
    {
        self::assertSame(self::SENTENCE, self::sanitizer()->sanitize(self::SENTENCE));
        self::assertSame('', self::sanitizer()->sanitize(''));
    }

    /**
     * Rows of `[text]`: every text above.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEverything(): iterable
    {
        $providers = [
            'controls'   => self::provideControls(),
            'utf-8'      => self::provideInvalidUtf8(),
            'secrets'    => self::provideSecrets(),
            'whole'      => self::provideWholeValues(),
            'capped'     => self::provideCapped(),
            'lookalikes' => self::provideLookalikes(),
        ];

        foreach ($providers as $group => $rows) {
            foreach ($rows as $name => $row) {
                yield $group . ': ' . $name => [$row[0]];
            }
        }

        yield 'a cut redaction' => [self::SIXTY . self::JWT];
        yield 'a cut pair' => [self::SIXTY . 'code=abc'];
        yield 'a cut element' => [self::SIXTY . '<code>abc</code>'];
        yield 'a cut closing tag' => [str_repeat('word ', 8) . 'ab <code>abc</code>'];
        yield 'a cut pair after a value' => [str_repeat('word ', 9) . 'code=abc&iss=x'];
        yield 'a cut JSON member' => [str_repeat('word ', 9) . '{"code":["abc"]}'];
        yield 'a sentence' => [self::SENTENCE];
    }

    /**
     * Sanitising twice changes nothing, at the default and the least cap.
     *
     * @param  string  $text
     * @return void
     */
    #[DataProvider('provideEverything')]
    public function testIsIdempotent(string $text): void
    {
        foreach ([self::sanitizer(), self::sanitizer(['max_diagnostic_length' => 64])] as $sanitizer) {
            $once = $sanitizer->sanitize($text);

            self::assertSame($once, $sanitizer->sanitize($once));
        }
    }

    /**
     * Rows of `[text]`: a secret, `SEKRIT`, in each form it may be redacted in.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCutForms(): iterable
    {
        yield from [
            'a query string'         => ['x=1&client_secret=SEKRIT,b;c&y=2 tail'],
            'a pair before a word'   => ['ab code=SEKRIT tail'],
            'a pair before another'  => ['a code=SEKRIT&x=1'],
            'repeated pairs'         => ['code=SEKRIT&state=SEKRIT tail'],
            'a quoted pair'          => ['password="SEKRIT SEKRIT" tail'],
            'a single-quoted pair'   => ['password=\'SEKRIT\\\'SEKRIT\' tail'],
            'an escaped quoted pair' => ['password=\"SEKRIT SEKRIT\" tail'],
            'an array pair'          => ['access_token=["SEKRIT", "SEKRIT"] tail'],
            'an arrow'               => ['client_secret => "SEKRIT" tail'],
            'a printed array'        => ['[client_secret] => SEKRIT [x] => 1'],
            'a colon'                => ['password: SEKRIT tail'],
            'a spaced name'          => ['private key=SEKRIT tail'],
            'a header'               => ['Authorization: Digest response="SEKRIT"'],
            'a JSON array'           => ['{"access_token":["SEKRIT",{"b":"c"}],"x":1}'],
            'escaped JSON'           => ['body {\"id_token\":\"SEKRIT,SEKRIT\",\"error\":\"bad\"}'],
            'doubly escaped JSON'    => ['{\\\\\"access_token\\\\\":\\\\\"SEKRIT,SEKRIT\\\\\"}'],
            'an element'             => ['<client_secret a="1">SEKRIT<b>c</b></client_secret> tail'],
            'a bare element'         => ['<password>SEKRIT</password> tail'],
            'a self-closing element' => ['<password value="SEKRIT"/> tail'],
            'an encoded query'       => ['redirect=https%3A%2F%2Fa%3Fcode%3DSEKRIT tail'],
            'an entity-encoded pair' => ['access_token&#61;SEKRIT tail'],
        ];
    }

    /**
     * Wherever the cap cuts a secret, it is gone and the result is stable.
     *
     * @param  string  $form
     * @return void
     */
    #[DataProvider('provideCutForms')]
    public function testIsIdempotentWhereverTheCapCuts(string $form): void
    {
        $sanitizer = self::sanitizer(['max_diagnostic_length' => 64]);

        for ($length = 0; $length <= 64; $length++) {

            $text = substr(str_repeat('word ', 13), 0, $length) . ' ' . $form;
            $once = $sanitizer->sanitize($text);

            self::assertSame($once, $sanitizer->sanitize($once), $text);
            self::assertStringNotContainsString('SEK', $once, $text);
        }
    }

    /**
     * A pattern that cannot run, such as past the backtrack limit, redacts all.
     *
     * @return void
     */
    public function testRedactsTheWholeTextWhenAPatternCannotRun(): void
    {
        $limit = (string) ini_get('pcre.backtrack_limit');

        ini_set('pcre.backtrack_limit', '1');

        try {
            $result = self::sanitizer()->sanitize('status code=abc <saml:Assertion ID="_a1">bob</saml:Assertion> done');
        } finally {
            ini_set('pcre.backtrack_limit', $limit);
        }

        self::assertSame('[redacted]', $result);
    }

    /**
     * A malformed setting fails closed rather than sanitising with a guess.
     *
     * @return void
     */
    public function testAMalformedSettingFailsClosed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('sso.logging.max_diagnostic_length must be an integer from 64 to 4096.');

        self::sanitizer(['max_diagnostic_length' => 63])->sanitize(self::SENTENCE);
    }

    /**
     * Rows of `[text, sanitised]`: query strings, forms and quoted pairs.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    private static function providePairValues(): iterable
    {
        yield from [
            'a value with a comma'            => ['client_secret=alpha,beta', 'client_secret=[redacted]'],
            'a value with a semicolon'        => ['client_secret=alpha;beta end', 'client_secret=[redacted] end'],
            'a value with an equals sign'     => ['client_secret=alpha=beta&state=x', 'client_secret=[redacted]&state=[redacted]'],
            'a value with an ampersand'       => ['client_secret=alpha&beta end', 'client_secret=[redacted] end'],
            'a value with quotes'             => ['client_secret=al"p h"\'a b\' end', 'client_secret=[redacted] end'],
            'a value with an open quote'      => ['client_secret=al"pha beta', 'client_secret=[redacted]'],
            'an array value'                  => ['access_token=["a", "leak"] end', 'access_token=[redacted] end'],
            'an object value'                 => ['password={"v": "leak"} end', 'password=[redacted] end'],
            'a parenthesised value'           => ['client_secret=(alpha, leak) end', 'client_secret=[redacted] end'],
            'a value with a bracketed part'   => ['client_secret=abc(def, leak) end', 'client_secret=[redacted] end'],
            'nested brackets'                 => ['password=[{"a": ["b c"]}, (d e)] end', 'password=[redacted] end'],
            'a bracket cut short'             => ['password=[alpha, leak', 'password=[redacted]'],
            'an escaped quoted value'         => ['access_token=\"leak more\" end', 'access_token=\"[redacted]\" end'],
            'an escaped pair in JSON'         => ['{"msg":"Digest password=\"alpha leak\""}', '{"msg":"Digest password=\"[redacted]\""}'],
            'a doubly escaped value'          => ['password=\\\\\"a leak\\\\\" end', 'password=\\\\\"[redacted]\\\\\" end'],
            'an arrow'                        => ['password=>"a leak" end', 'password=>"[redacted]" end'],
            'a spaced arrow'                  => ['client_secret => "leak" end', 'client_secret => "[redacted]" end'],
            'an unquoted arrow'               => ['client_secret=>abc end', 'client_secret=>[redacted] end'],
            'an exported array'               => ['[\'client_secret\' => \'leak\', \'x\' => 1]', '[\'client_secret\' => \'[redacted]\', \'x\' => 1]'],
            'a printed array'                 => ['Array ( [client_secret] => leak [x] => 1 )', 'Array ( [client_secret] => [redacted] [x] => 1 )'],
            'a colon'                         => ['password: hunter2 end', 'password: [redacted] end'],
            'a colon and a quoted value'      => ['access_token: "leak more" end', 'access_token: "[redacted]" end'],
            'an unquoted object key'          => ['{client_secret: \'leak\'}', '{client_secret: \'[redacted]\'}'],
            'a single-quoted object key'      => ['{\'client_secret\': \'leak\'}', '{\'client_secret\': \'[redacted]\'}'],
            'an Authorization header'         => ['Authorization: Bearer mF_9.B5f-4.1JqM end', 'Authorization: [redacted]'],
            'another scheme'                  => ['authorization: Token leak', 'authorization: [redacted]'],
            'a Digest header'                 => ['Authorization: Digest username="x", response="leak"', 'Authorization: [redacted]'],
            'a Proxy-Authorization header'    => ['Proxy-Authorization: Basic leak', 'Proxy-Authorization: [redacted]'],
            'a Cookie header'                 => ['Cookie: sid=leak; other=def', 'Cookie: [redacted]'],
            'a Set-Cookie header'             => ['Set-Cookie: session=leak; Path=/; HttpOnly', 'Set-Cookie: [redacted]'],
            'a spaced name'                   => ['private key=leak end', 'private key=[redacted] end'],
            'a spaced SAML name'              => ['saml response=leak end', 'saml response=[redacted] end'],
            'a spaced name and a colon'       => ['Private key: leak end', 'Private key: [redacted] end'],
            'a dotted name'                   => ['credentials.password=leak end', 'credentials.password=[redacted] end'],
            'a deeper dotted name'            => ['sso.oidc.client_secret=leak end', 'sso.oidc.client_secret=[redacted] end'],
            'a slashed name'                  => ['user/password=leak end', 'user/password=[redacted] end'],
            'a header-style name'             => ['x-client-secret=leak end', 'x-client-secret=[redacted] end'],
            'an entity-encoded separator'     => ['access_token&#61;short end', '[redacted] end'],
            'an entity-encoded element'       => ['body &lt;password&gt;leak&lt;/password&gt; end', 'body [redacted] end'],
            'a value with brackets'           => ['password=(a)[b]<c>{d} end', 'password=[redacted] end'],
            'a value with a hash'             => ['password=a#b end', 'password=[redacted] end'],
            'a percent-encoded name'          => ['?client%5fsecret=short-secret', '?client%5fsecret=[redacted]'],
            'an upper-case encoded name'      => ['?client%5Fsecret=short-secret&x=1', '?client%5Fsecret=[redacted]&x=1'],
            'a plus-encoded name'             => ['client+secret=short-secret', 'client+secret=[redacted]'],
            'a wholly encoded name'           => ['%63%6F%64%65=abc', '%63%6F%64%65=[redacted]'],
            'a double-encoded name'           => ['client%255Fsecret=abc', 'client%255Fsecret=[redacted]'],
            'an encoded and plus value'       => ['client_secret=al%2Cpha+be%26ta%3D', 'client_secret=[redacted]'],
            'repeated keys'                   => ['code=a&code=b,c&code=d', 'code=[redacted]&code=[redacted]&code=[redacted]'],
            'keys in mixed case'              => ['Client_Secret=a,b&ACCESS_TOKEN=c;d&Nonce=e', 'Client_Secret=[redacted]&ACCESS_TOKEN=[redacted]&Nonce=[redacted]'],
            'an array-style name'             => ['client_secret[]=a,b&client_secret[]=c', 'client_secret[]=[redacted]&client_secret[]=[redacted]'],
            'a nested form name'              => ['user[password]=a,b&user[name]=bob', 'user[password]=[redacted]&user[name]=bob'],
            'an encoded nested form name'     => ['user%5Bpassword%5D=a', 'user%5Bpassword%5D=[redacted]'],
            'an unterminated quoted value'    => ['client_secret="alpha beta', 'client_secret="[redacted]"'],
            'a quoted value, escaped quote'   => ['password="a\"b c" end', 'password="[redacted]" end'],
            'a quoted value with separators'  => ['client_secret=\'a=b&c,d;e f\' end', 'client_secret=\'[redacted]\' end'],
            'an escaped attribute'            => ['<x State=\"a,b c\"> end', '<x State=\"[redacted]\"> end'],
            'an encoded query in a value'     => ['redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb%3Fcode%3Dabc%26state%3Dxyz end', '[redacted] end'],
            'an encoded pair under no key'    => ['callback cb%3Fcode%3Dabc', 'callback [redacted]'],
            'an encoded JSON body'            => ['body %7B%22access_token%22%3A%5B%22x%22%5D%7D', 'body [redacted]'],
            'an encoded name and a separator' => ['x%26client_secret=abc', 'x%26client_secret=[redacted]'],
        ];
    }

    /**
     * Rows of `[text, sanitised]`: JSON members, plain and escaped.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    private static function provideJsonValues(): iterable
    {
        yield from [
            'a JSON array'                => ['{"access_token":["short-token-value"]}', '{"access_token":"[redacted]"}'],
            'a JSON object'               => ['{"client_secret":{"value":"x","nested":{"a":[1,2]}},"error":"bad"}', '{"client_secret":"[redacted]","error":"bad"}'],
            'a JSON null'                 => ['{"state":null,"error":"bad"}', '{"state":"[redacted]","error":"bad"}'],
            'a JSON negative float'       => ['{"code":-1.5e3}', '{"code":"[redacted]"}'],
            'a JSON false with spaces'    => ['{"nonce" : false }', '{"nonce" : "[redacted]" }'],
            'a JSON string of separators' => ['{"password":"a,b;c=d&e\'f\"g}h]","user":"bob"}', '{"password":"[redacted]","user":"bob"}'],
            'a nested JSON member'        => ['{"data":{"tokens":{"refresh_token":"abc"}},"ok":true}', '{"data":{"tokens":{"refresh_token":"[redacted]"}},"ok":true}'],
            'repeated JSON keys'          => ['[{"code":"a"},{"code":["b",{"c":1}]}]', '[{"code":"[redacted]"},{"code":"[redacted]"}]'],
            'a JSON key in mixed case'    => ['{"Access-Token":[true,false]}', '{"Access-Token":"[redacted]"}'],
            'a unicode-escaped JSON key'  => ['{"client_secret":"x"}', '{"client_secret":"[redacted]"}'],
            'a JSON array cut short'      => ['{"access_token":["abc", "de', '{"access_token":"[redacted]"'],
            'a JSON string cut short'     => ['{"access_token":"abc de', '{"access_token":"[redacted]"'],
            'a bare JSON-like value'      => ['"state": some text, more', '"state": "[redacted]", more'],
            'an escaped JSON array'       => ['body {\"access_token\":[\"a,b\"],\"error\":\"bad\"}', 'body {\"access_token\":\"[redacted]\",\"error\":\"bad\"}'],
            'an escaped JSON object'      => ['{\"password\":{\"v\":\"a\\\\\"}b\"},\"x\":1}', '{\"password\":\"[redacted]\",\"x\":1}'],
            'an escaped unicode JSON key' => ['{\"client\\\u005fsecret\":\"x\"}', '{\"client\\\u005fsecret\":\"[redacted]\"}'],
            'doubly escaped JSON'         => ['{\\\\\"access_token\\\\\":\\\\\"a,b\\\\\"}', '{\\\\\"access_token\\\\\":\\\\\"[redacted]\\\\\"}'],
            'a doubly escaped quote'      => ['{\\\\\"password\\\\\":\\\\\"a\\\\\\\\\\\\\"b, c\\\\\"}', '{\\\\\"password\\\\\":\\\\\"[redacted]\\\\\"}'],
            'a spaced JSON key'           => ['{"private key":"a","x":1}', '{"private key":"[redacted]","x":1}'],
            'a dotted JSON key'           => ['{"credentials.password":"b","x":1}', '{"credentials.password":"[redacted]","x":1}'],
            'a slashed JSON key'          => ['{"user/password":"c","x":1}', '{"user/password":"[redacted]","x":1}'],
            'an escaped JSON number'      => ['{\"code\":123,\"x\":1}', '{\"code\":\"[redacted]\",\"x\":1}'],
            'JSON with an encoded secret' => ['{"next":"/cb?code%3Dabc"} end', '[redacted] end'],
        ];
    }

    /**
     * Rows of `[text, sanitised]`: XML elements with children or cut short.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    private static function provideElementValues(): iterable
    {
        yield from [
            'an element with children'   => ['<client_secret><v>a</v><w/></client_secret> end', '<client_secret>[redacted]</client_secret> end'],
            'a prefixed nested element'  => ['<p:State a="1"><x>a</x></p:State> <p:Issuer>idp</p:Issuer>', '<p:State a="1">[redacted]</p:State> <p:Issuer>idp</p:Issuer>'],
            'an element cut short'       => ['status <code>abc def', 'status <code>[redacted]'],
            'nested same-named elements' => ['<code><code>a</code>b<code/></code> end', '<code>[redacted]</code> end'],
            'a self-closing element'     => ['<password value="hunter2"/> end', '<password [redacted]/> end'],
            'a spaced self-closing one'  => ['<p:State a="1" b=\'2\' /> end', '<p:State [redacted]/> end'],
        ];
    }

    /**
     * A sanitiser over the logging settings given.
     *
     * @param  array<string, mixed>  $logging
     * @return \SineMacula\Laravel\Sso\Logging\DiagnosticSanitizer
     */
    private static function sanitizer(array $logging = []): DiagnosticSanitizer
    {
        return new DiagnosticSanitizer(new LoggingSettings(new Repository(['sso' => ['logging' => $logging]])));
    }
}
