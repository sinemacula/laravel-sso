<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Metadata\DiscoveryDocument;
use Tests\Concerns\DumpsValues;
use Tests\TestCase;

/**
 * Feature tests for reading an OpenID Connect discovery document.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiscoveryDocument::class)]
final class DiscoveryDocumentTest extends TestCase
{
    use DumpsValues;

    /** @var string The issuer every document is read for. */
    private const string ISSUER = 'https://op.example.test';

    /** @var string What a document's changes give for a member it leaves out. */
    private const string ABSENT = "\0absent";

    /** @var int The cap every document is read under unless a test gives another. */
    private const int CAP = 65536;

    /** @var string A number too large for an integer. */
    private const string LARGE = '123456789012345678901234567890';

    /**
     * A document every rule accepts is read into typed values, the algorithms
     * in the package's own order.
     *
     * @return void
     */
    public function testADocumentEveryRuleAcceptsIsRead(): void
    {
        $document = self::read();

        self::assertTrue($document->isRead());
        self::assertNull($document->reason);
        self::assertSame([
            'issuer'                 => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/authorize',
            'token_endpoint'         => self::ISSUER . '/token',
            'jwks_uri'               => self::ISSUER . '/jwks',
            'userinfo_endpoint'      => self::ISSUER . '/userinfo',
            'returns_iss'            => true,
            'id_token_algorithms'    => ['RS256', 'PS256', 'ES256', 'ES512'],
        ], $document->settings());
        self::assertSame(self::ISSUER . '/jwks', $document->jwksUri());
        self::assertSame(['RS256', 'PS256', 'ES256', 'ES512'], $document->algorithms());
        self::assertSame(['private_key_jwt', 'client_secret_basic'], $document->authMethods());
    }

    /**
     * Rows of `[changes, setting, value]`; a setting of `ABSENT` is left out.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: mixed}>
     */
    public static function provideAcceptedDocuments(): iterable
    {
        $at2048 = self::ISSUER . '/' . str_repeat('a', 2048 - strlen(self::ISSUER) - 1);

        yield from [
            'no UserInfo endpoint'          => [['userinfo_endpoint' => self::ABSENT], 'userinfo_endpoint', self::ABSENT],
            'no RFC 9207 flag'              => [['authorization_response_iss_parameter_supported' => self::ABSENT], 'returns_iss', false],
            'the RFC 9207 flag off'         => [['authorization_response_iss_parameter_supported' => false], 'returns_iss', false],
            'an endpoint with a query'      => [['token_endpoint' => self::ISSUER . '/token?a=1'], 'token_endpoint', self::ISSUER . '/token?a=1'],
            'an endpoint of 2048 bytes'     => [['authorization_endpoint' => $at2048], 'authorization_endpoint', $at2048],
            'no subject types'              => [['subject_types_supported' => self::ABSENT], 'issuer', self::ISSUER],
            'subject types left empty'      => [['subject_types_supported' => []], 'issuer', self::ISSUER],
            'no PKCE methods'               => [['code_challenge_methods_supported' => self::ABSENT], 'issuer', self::ISSUER],
            'S256 among other methods'      => [['code_challenge_methods_supported' => ['plain', 'S256']], 'issuer', self::ISSUER],
            'code among other types'        => [['response_types_supported' => ['id_token', 'code']], 'issuer', self::ISSUER],
            'an algorithm among unknowns'   => [['id_token_signing_alg_values_supported' => ['none', 'HS256', 'RS384']], 'id_token_algorithms', ['RS384']],
            'a member it does not name'     => [['unknown_member' => ['nested' => 1]], 'issuer', self::ISSUER],
            'an unnamed member of any type' => [['registration_endpoint' => 1], 'issuer', self::ISSUER],
        ];
    }

    /**
     * What a document may leave out or say otherwise is read, and gives the
     * setting.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $setting
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideAcceptedDocuments')]
    public function testADocumentMayLeaveOutOrSayOtherwise(array $changes, string $setting, mixed $value): void
    {
        $document = self::read($changes);

        self::assertTrue($document->isRead());

        if ($value === self::ABSENT) {
            self::assertArrayNotHasKey($setting, $document->settings());

            return;
        }

        self::assertSame($value, $document->settings()[$setting] ?? null);
    }

    /**
     * A document that lists no client authentication methods lists none.
     *
     * @return void
     */
    public function testADocumentListingNoMethodsListsNone(): void
    {
        self::assertSame([], self::read(['token_endpoint_auth_methods_supported' => self::ABSENT])->authMethods());
        self::assertSame(['client_secret_post'], self::read(['token_endpoint_auth_methods_supported' => ['client_secret_post']])->authMethods());
    }

    /**
     * Rows of `[changes, reason]`: every rule's refusal.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusedDocuments(): iterable
    {
        $over2048 = self::ISSUER . '/' . str_repeat('a', 2049 - strlen(self::ISSUER) - 1);

        yield from [
            'an issuer with a trailing slash'   => [['issuer' => self::ISSUER . '/'], FailureReason::ISSUER_MISMATCH],
            'an issuer of another case'         => [['issuer' => 'https://OP.example.test'], FailureReason::ISSUER_MISMATCH],
            'an issuer with a path'             => [['issuer' => self::ISSUER . '/tenant'], FailureReason::ISSUER_MISMATCH],
            'no issuer'                         => [['issuer' => self::ABSENT], FailureReason::ISSUER_MISMATCH],
            'an issuer that is not a string'    => [['issuer' => 1], FailureReason::ISSUER_MISMATCH],
            'an issuer that is null'            => [['issuer' => null], FailureReason::ISSUER_MISMATCH],
            'an http authorization endpoint'    => [['authorization_endpoint' => 'http://op.example.test/authorize'], FailureReason::DISCOVERY_INVALID],
            'no authorization endpoint'         => [['authorization_endpoint' => self::ABSENT], FailureReason::DISCOVERY_INVALID],
            'a token endpoint with userinfo'    => [['token_endpoint' => 'https://user:pass@op.example.test/token'], FailureReason::DISCOVERY_INVALID],
            'no token endpoint'                 => [['token_endpoint' => self::ABSENT], FailureReason::DISCOVERY_INVALID],
            'no JWKS URI'                       => [['jwks_uri' => self::ABSENT], FailureReason::DISCOVERY_INVALID],
            'a JWKS URI with a fragment'        => [['jwks_uri' => self::ISSUER . '/jwks#a'], FailureReason::DISCOVERY_INVALID],
            'a JWKS URI that is not a string'   => [['jwks_uri' => ['https://op.example.test/jwks']], FailureReason::DISCOVERY_INVALID],
            'an endpoint of 2049 bytes'         => [['authorization_endpoint' => $over2048], FailureReason::DISCOVERY_INVALID],
            'an http UserInfo endpoint'         => [['userinfo_endpoint' => 'http://op.example.test/userinfo'], FailureReason::DISCOVERY_INVALID],
            'a UserInfo endpoint that is null'  => [['userinfo_endpoint' => null], FailureReason::DISCOVERY_INVALID],
            'no response types'                 => [['response_types_supported' => self::ABSENT], FailureReason::DISCOVERY_INVALID],
            'response types without code'       => [['response_types_supported' => ['id_token', 'code token']], FailureReason::DISCOVERY_INVALID],
            'response types that are a string'  => [['response_types_supported' => 'code'], FailureReason::DISCOVERY_INVALID],
            'response types that are a map'     => [['response_types_supported' => ['a' => 'code']], FailureReason::DISCOVERY_INVALID],
            'response types with a number'      => [['response_types_supported' => ['code', 1]], FailureReason::DISCOVERY_INVALID],
            'subject types that are a string'   => [['subject_types_supported' => 'public'], FailureReason::DISCOVERY_INVALID],
            'subject types with a number'       => [['subject_types_supported' => [1]], FailureReason::DISCOVERY_INVALID],
            'PKCE without S256'                 => [['code_challenge_methods_supported' => ['plain']], FailureReason::DISCOVERY_INVALID],
            'PKCE left empty'                   => [['code_challenge_methods_supported' => []], FailureReason::DISCOVERY_INVALID],
            'PKCE methods that are a string'    => [['code_challenge_methods_supported' => 'S256'], FailureReason::DISCOVERY_INVALID],
            'PKCE methods with a number'        => [['code_challenge_methods_supported' => ['S256', 1]], FailureReason::DISCOVERY_INVALID],
            'no algorithms'                     => [['id_token_signing_alg_values_supported' => self::ABSENT], FailureReason::DISCOVERY_INVALID],
            'no algorithm on the package list'  => [['id_token_signing_alg_values_supported' => ['none', 'HS256', 'rs256']], FailureReason::DISCOVERY_INVALID],
            'algorithms left empty'             => [['id_token_signing_alg_values_supported' => []], FailureReason::DISCOVERY_INVALID],
            'algorithms that are a string'      => [['id_token_signing_alg_values_supported' => 'RS256'], FailureReason::DISCOVERY_INVALID],
            'algorithms that are a map'         => [['id_token_signing_alg_values_supported' => ['RS256' => true]], FailureReason::DISCOVERY_INVALID],
            'algorithms with a number'          => [['id_token_signing_alg_values_supported' => ['RS256', 1]], FailureReason::DISCOVERY_INVALID],
            'methods that are a string'         => [['token_endpoint_auth_methods_supported' => 'client_secret_basic'], FailureReason::DISCOVERY_INVALID],
            'methods with a number'             => [['token_endpoint_auth_methods_supported' => ['client_secret_basic', 1]], FailureReason::DISCOVERY_INVALID],
            'an RFC 9207 flag that is a string' => [['authorization_response_iss_parameter_supported' => 'true'], FailureReason::DISCOVERY_INVALID],
            'an RFC 9207 flag that is a number' => [['authorization_response_iss_parameter_supported' => 1], FailureReason::DISCOVERY_INVALID],
            'an RFC 9207 flag that is null'     => [['authorization_response_iss_parameter_supported' => null], FailureReason::DISCOVERY_INVALID],
            'response types an object'          => [['response_types_supported' => (object) ['code']], FailureReason::DISCOVERY_INVALID],
            'algorithms an object'              => [['id_token_signing_alg_values_supported' => (object) ['RS256']], FailureReason::DISCOVERY_INVALID],
            'subject types an object'           => [['subject_types_supported' => (object) ['public']], FailureReason::DISCOVERY_INVALID],
            'subject types an empty object'     => [['subject_types_supported' => new \stdClass], FailureReason::DISCOVERY_INVALID],
            'PKCE methods an object'            => [['code_challenge_methods_supported' => (object) ['S256']], FailureReason::DISCOVERY_INVALID],
            'PKCE methods an empty object'      => [['code_challenge_methods_supported' => new \stdClass], FailureReason::DISCOVERY_INVALID],
            'methods an object'                 => [['token_endpoint_auth_methods_supported' => (object) ['client_secret_basic']], FailureReason::DISCOVERY_INVALID],
            'methods an empty object'           => [['token_endpoint_auth_methods_supported' => new \stdClass], FailureReason::DISCOVERY_INVALID],
        ];
    }

    /**
     * Each rule refuses the document with its reason, and a refused document
     * holds no values.
     *
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusedDocuments')]
    public function testEachRuleRefusesTheDocument(array $changes, FailureReason $reason): void
    {
        $document = self::read($changes);

        self::assertFalse($document->isRead());
        self::assertSame($reason, $document->reason);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A refused discovery document holds no values.');

        $document->settings();
    }

    /**
     * Rows of `[member, value, reason]`: a member written as a number too large
     * for an integer, against an issuer of the same digits.
     *
     * @return iterable<string, array{0: string, 1: string, 2: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideLargeNumbers(): iterable
    {
        yield from [
            'the issuer'      => ['issuer', self::LARGE, FailureReason::ISSUER_MISMATCH],
            'the JWKS URI'    => ['jwks_uri', self::LARGE, FailureReason::DISCOVERY_INVALID],
            'an algorithm'    => ['id_token_signing_alg_values_supported', '["RS256",' . self::LARGE . ']', FailureReason::DISCOVERY_INVALID],
            'a response type' => ['response_types_supported', '["code",' . self::LARGE . ']', FailureReason::DISCOVERY_INVALID],
            'a method'        => ['token_endpoint_auth_methods_supported', '[' . self::LARGE . ']', FailureReason::DISCOVERY_INVALID],
            'a subject type'  => ['subject_types_supported', '[' . self::LARGE . ']', FailureReason::DISCOVERY_INVALID],
        ];
    }

    /**
     * A number is never read as a string of its digits, an issuer of those
     * digits included.
     *
     * @param  string  $member
     * @param  string  $value
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideLargeNumbers')]
    public function testANumberIsNeverItsDigits(string $member, string $value, FailureReason $reason): void
    {
        $json = (string) json_encode([...self::document(), 'issuer' => self::LARGE, $member => 'the-number'], JSON_UNESCAPED_SLASHES);

        self::assertSame($reason, DiscoveryDocument::read(str_replace('"the-number"', $value, $json), self::LARGE, self::CAP)->reason);
    }

    /**
     * Rows of `[body]`: what is not one JSON object read strictly.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnreadableBodies(): iterable
    {
        $backslash = chr(92);
        $valid     = substr((string) json_encode(self::document(), JSON_UNESCAPED_SLASHES), 1);

        yield from [
            'nothing'                 => [''],
            'not JSON'                => ['<html></html>'],
            'truncated'               => ['{"issuer":'],
            'invalid UTF-8'           => ["{\"issuer\":\"\xff\"}"],
            'a list'                  => ['[]'],
            'a list of the document'  => ['[' . json_encode(self::document()) . ']'],
            'a string'                => ['"https://op.example.test"'],
            'a number'                => ['1'],
            'null'                    => ['null'],
            'true'                    => ['true'],
            'the issuer repeated'     => ['{"issuer":"' . self::ISSUER . '",' . $valid],
            'the issuer escaped'      => ['{"' . $backslash . 'u0069ssuer":"' . self::ISSUER . '",' . $valid],
            'the JWKS URI repeated'   => ['{"jwks_uri":"https://attacker.example.test/jwks",' . $valid],
            'a nested member twice'   => ['{"unknown_member":{"a":1,"a":2},' . $valid],
            'a nested member escaped' => ['{"unknown_member":{"a":1,"' . $backslash . 'u0061":2},' . $valid],
        ];
    }

    /**
     * What is not one JSON object read strictly is `discovery_invalid`.
     *
     * @param  string  $body
     * @return void
     */
    #[DataProvider('provideUnreadableBodies')]
    public function testWhatIsNotOneStrictObjectIsInvalid(string $body): void
    {
        $document = DiscoveryDocument::read($body, self::ISSUER, self::CAP);

        self::assertFalse($document->isRead());
        self::assertSame(FailureReason::DISCOVERY_INVALID, $document->reason);
    }

    /**
     * An empty object names no issuer.
     *
     * @return void
     */
    public function testAnEmptyObjectNamesNoIssuer(): void
    {
        self::assertSame(FailureReason::ISSUER_MISMATCH, DiscoveryDocument::read('{}', self::ISSUER, self::CAP)->reason);
    }

    /**
     * The document's issuer is judged before its other members.
     *
     * @return void
     */
    public function testTheIssuerIsJudgedFirst(): void
    {
        self::assertSame(FailureReason::ISSUER_MISMATCH, self::read(['issuer' => self::ISSUER . '/', 'jwks_uri' => self::ABSENT])->reason);
    }

    /**
     * Rows of `[cap offset, read]`: the cap against the body's length.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideCaps(): iterable
    {
        yield from [
            'a cap a byte over'  => [1, true],
            'a cap at it'        => [0, true],
            'a cap a byte under' => [-1, false],
        ];
    }

    /**
     * A body is read at the cap and under it, and refused over it.
     *
     * @param  int  $offset
     * @param  bool  $read
     * @return void
     */
    #[DataProvider('provideCaps')]
    public function testTheSizeCapHolds(int $offset, bool $read): void
    {
        $body     = (string) json_encode(self::document(), JSON_UNESCAPED_SLASHES);
        $document = DiscoveryDocument::read($body, self::ISSUER, strlen($body) + $offset);

        self::assertSame([$read, $read ? null : FailureReason::DISCOVERY_INVALID], [$document->isRead(), $document->reason]);
    }

    /**
     * No dump or `json_encode()` of a read document shows a value of it: only
     * the names of its settings.
     *
     * @return void
     */
    public function testADumpShowsNoValue(): void
    {
        $document = self::read();
        $names    = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'returns_iss', 'id_token_algorithms'];

        self::assertSame(['read' => true, 'reason' => null, 'settings' => $names], $document->__debugInfo());
        self::assertSame(['read' => true, 'reason' => null, 'settings' => $names], $document->jsonSerialize());
        self::assertStringNotContainsString('op.example.test', (string) json_encode($document));

        foreach (self::dumps($document) as $dump) {
            self::assertStringNotContainsString('op.example.test', $dump);
            self::assertStringNotContainsString('private_key_jwt', $dump);
        }

        self::assertSame(['read' => false, 'reason' => 'discovery_invalid', 'settings' => []], DiscoveryDocument::read('[]', self::ISSUER, self::CAP)->__debugInfo());
    }

    /**
     * A document refuses to be serialised or unserialised.
     *
     * @return void
     */
    public function testADocumentRefusesToBeSerialized(): void
    {
        $document = self::read();

        self::assertSame('A discovery document cannot be serialised.', self::refusal(static fn (): string => serialize($document)));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A discovery document cannot be unserialised.');

        $document->__unserialize([]);
    }

    /**
     * The message of the `LogicException` the work throws, or none.
     *
     * @param  \Closure(): mixed  $work
     * @return ?string
     */
    private static function refusal(\Closure $work): ?string
    {
        try {
            $work();
        } catch (\LogicException $exception) {
            return $exception->getMessage();
        }

        return null;
    }

    /**
     * The document with the changes laid over a valid one, read for the issuer.
     *
     * @param  array<string, mixed>  $changes
     * @return \SineMacula\Laravel\Sso\Metadata\DiscoveryDocument
     */
    private static function read(array $changes = []): DiscoveryDocument
    {
        return DiscoveryDocument::read((string) json_encode(self::document($changes), JSON_UNESCAPED_SLASHES), self::ISSUER, self::CAP);
    }

    /**
     * A document every rule accepts, with the changes laid over it; a change of
     * `ABSENT` removes the member.
     *
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    private static function document(array $changes = []): array
    {
        $document = [
            'issuer'                                         => self::ISSUER,
            'authorization_endpoint'                         => self::ISSUER . '/authorize',
            'token_endpoint'                                 => self::ISSUER . '/token',
            'jwks_uri'                                       => self::ISSUER . '/jwks',
            'userinfo_endpoint'                              => self::ISSUER . '/userinfo',
            'response_types_supported'                       => ['code'],
            'subject_types_supported'                        => ['public'],
            'code_challenge_methods_supported'               => ['S256'],
            'id_token_signing_alg_values_supported'          => ['ES512', 'ES256', 'none', 'HS256', 'PS256', 'RS256'],
            'token_endpoint_auth_methods_supported'          => ['private_key_jwt', 'client_secret_basic'],
            'authorization_response_iss_parameter_supported' => true,
        ];

        return array_filter([...$document, ...$changes], static fn (mixed $value): bool => $value !== self::ABSENT);
    }
}
