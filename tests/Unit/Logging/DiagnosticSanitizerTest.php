<?php

declare(strict_types = 1);

namespace Tests\Unit\Logging;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Logging\DiagnosticSanitizer;
use SineMacula\Laravel\Sso\Logging\LoggingSettings;

/**
 * Unit tests for the diagnostic sanitiser (SSO-5.7, SSO-9.8, SSO-11.9): every
 * control and bidirectional character removed, invalid UTF-8 scrubbed, every
 * kind of secret redacted, the configured keys honoured, the length capped,
 * ordinary text left alone, and sanitising idempotent.
 *
 * The token and key fixtures are built from their parts, so no secret scanner
 * takes them for real credentials.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiagnosticSanitizer::class)]
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
     * Rows of `[text, sanitised]`: tabs and line breaks, which become one
     * space, and every other control, removed.
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
     * Each control is removed, and tabs, line breaks and separators become a
     * single space, so a diagnostic cannot forge a log line or reorder what a
     * reader sees.
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
     * Rows of `[text, sanitised]`: each kind of secret and what it is redacted
     * to.
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
            'a Bearer header'         => ['Authorization: Bearer mF_9.B5f-4.1JqM end', 'Authorization: Bearer [redacted] end'],
            'a lower-case bearer'     => ['authorization: bearer mF_9.B5f-4.1JqM', 'authorization: bearer [redacted]'],
            'a Basic header'          => ['Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW', 'Authorization: Basic [redacted]'],
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
        ];
    }

    /**
     * Text that only looks like a secret is kept: a key is redacted only when
     * its whole name normalises to a redacted key, and only a run of 40 or more
     * characters is taken for a secret by its shape.
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
     * A key added in `sso.logging.redacted_keys` is redacted in every form,
     * alongside the built-in ones; without it, it is not.
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
     * Rows of `[text, sanitised]`: text at, around and past a cap of 64
     * characters.
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
     * Text is cut to the configured length in characters, not bytes: text of
     * exactly the length is untouched, and longer text keeps one character
     * fewer and ends in `…`, so it is exactly the length.
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
     * Redaction happens before the cap, so a secret straddling the cut is never
     * left half there.
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
        yield 'a sentence' => [self::SENTENCE];
    }

    /**
     * Sanitising sanitised text changes nothing, at the default cap and at the
     * least one.
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
     * A pattern that cannot run over the text (here, a PCRE backtrack limit too
     * low for any of them) redacts the text whole rather than letting it
     * through unredacted.
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
