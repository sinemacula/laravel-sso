<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\UserInfoReader;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for the UserInfo request and its answer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UserInfoReader::class)]
final class UserInfoReaderTest extends TestCase
{
    /** @var string The issuer of the validated ID token. */
    private const string ISSUER = 'https://op.example.test';

    /** @var string The connection's UserInfo endpoint. */
    private const string ENDPOINT = 'https://op.example.test/userinfo';

    /** @var string The access token the token endpoint answered. */
    private const string ACCESS_TOKEN = 'the-access-token';

    /** @var string The subject of the validated ID token. */
    private const string SUBJECT = 'the-subject';

    /** @var string A body that passes. */
    private const string BODY = '{"sub":"the-subject"}';

    /** @var string The content type of a JSON answer. */
    private const string JSON_TYPE = 'application/json';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the request is sent through. */
    private FakeFetcher $fetcher;

    /**
     * Bind the fake fetcher.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Fetcher::class, $this->fetcher);
    }

    /**
     * One `GET` to the connection's endpoint carries the access token and no
     * other credential, with the default timeout and cap.
     *
     * @return void
     */
    public function testTheRequestIsPinned(): void
    {
        $this->answered(self::jsonAnswer(self::BODY));

        $requests = $this->fetcher->requests();

        self::assertCount(1, $requests);

        $request = $requests[0];

        self::assertSame(FetchPurpose::USERINFO, $request->purpose);
        self::assertSame('GET', $request->method());
        self::assertSame(self::ENDPOINT, $request->url);
        self::assertSame([], $request->form());
        self::assertSame(CredentialKind::ACCESS_TOKEN, $request->credentials?->kind);
        self::assertSame(self::ACCESS_TOKEN, $request->credentials->secret());
        self::assertNull($request->credentials->clientId);
        self::assertSame(10, $request->timeoutSeconds);
        self::assertSame(65536, $request->maxBytes);
    }

    /**
     * The request is held to the configured timeout and cap.
     *
     * @return void
     */
    public function testTheRequestTakesTheConfiguredTimeoutAndCap(): void
    {
        config()->set('sso.oidc.userinfo_timeout_seconds', 3);
        config()->set('sso.oidc.max_userinfo_bytes', 4096);

        $this->answered(self::jsonAnswer(self::BODY));

        self::assertSame(3, $this->fetcher->requests()[0]->timeoutSeconds);
        self::assertSame(4096, $this->fetcher->requests()[0]->maxBytes);
    }

    /**
     * A connection that fetches UserInfo but names no endpoint is the caller's
     * mistake, since only a complete connection is used.
     *
     * @return void
     */
    public function testNoEndpointIsTheCallersMistake(): void
    {
        $options = OidcOptions::of(new IdentifiedConnection('c1', settings: ['fetch_userinfo' => true]));

        $this->expectExceptionObject(new \LogicException('A connection that fetches UserInfo names its endpoint; only a complete connection is used.'));

        $this->reader()->fetch($options, self::tokens());
    }

    /**
     * A request inside a transaction on the storage connection is refused
     * before anything is sent, so a provider call never holds a lock.
     *
     * @return void
     */
    public function testARequestInsideATransactionIsRefused(): void
    {
        $this->fetcher->respond(self::ENDPOINT, self::jsonAnswer(self::BODY));

        $message = null;

        DB::beginTransaction();

        try {
            $this->reader()->fetch(self::readerOptions(), self::tokens());
        } catch (\LogicException $exception) {
            $message = $exception->getMessage();
        } finally {
            DB::rollBack();
        }

        self::assertSame('A UserInfo request is sent outside any transaction on the package\'s storage connection: a provider call never holds a lock.', $message);
        $this->fetcher->assertNothingFetched();
    }

    /**
     * Rows of `[status, reason]`: what each status comes to, on a body that
     * would otherwise pass.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideStatuses(): iterable
    {
        yield '199' => [199, FailureReason::FETCH_FAILED];
        yield '200' => [200, null];
        yield '201' => [201, null];
        yield '299' => [299, null];
        yield '300' => [300, FailureReason::FETCH_FAILED];
        yield '302' => [302, FailureReason::FETCH_FAILED];
        yield '400' => [400, FailureReason::FETCH_FAILED];
        yield '401' => [401, FailureReason::PROVIDER_ERROR];
        yield '402' => [402, FailureReason::FETCH_FAILED];
        yield '403' => [403, FailureReason::PROVIDER_ERROR];
        yield '404' => [404, FailureReason::FETCH_FAILED];
        yield '500' => [500, FailureReason::FETCH_FAILED];
        yield '503' => [503, FailureReason::FETCH_FAILED];
    }

    /**
     * `401` and `403` are the provider's error, any other status outside `2xx`
     * a failed fetch, and a `2xx` goes on to its body.
     *
     * @param  int  $status
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideStatuses')]
    public function testEveryStatus(int $status, ?FailureReason $reason): void
    {
        self::assertSame($reason, $this->answered(FetchResult::fetched($status, ['Content-Type' => self::JSON_TYPE], self::BODY)));
    }

    /**
     * A request refused before it was sent is `fetch_refused`, with one
     * attempt.
     *
     * @return void
     */
    public function testARefusedRequestIsFetchRefused(): void
    {
        self::assertSame(FailureReason::FETCH_REFUSED, $this->answered(FetchResult::refused()));
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * A timeout or any other failed request is `fetch_failed`, with no retry.
     *
     * @return void
     */
    public function testATimeoutIsFetchFailed(): void
    {
        self::assertSame(FailureReason::FETCH_FAILED, $this->answered(FetchResult::failed()));
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * Rows of `[headers, reason]`: the content types of an answer whose body
     * would otherwise pass.
     *
     * @return iterable<string, array{0: array<string, string>, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideContentTypes(): iterable
    {
        yield 'JSON' => [['Content-Type' => 'application/json'], null];
        yield 'JSON with a charset' => [['Content-Type' => 'application/json; charset=utf-8'], null];
        yield 'none' => [[], null];
        yield 'another type' => [['Content-Type' => 'text/plain'], null];
        yield 'a type that only starts the same' => [['Content-Type' => 'application/jwt-like'], null];
        yield 'a JWT' => [['Content-Type' => 'application/jwt'], FailureReason::USERINFO_INVALID];
        yield 'a JWT in another case' => [['Content-Type' => 'APPLICATION/JWT'], FailureReason::USERINFO_INVALID];
        yield 'a JWT with a charset' => [['Content-Type' => 'application/jwt; charset=utf-8'], FailureReason::USERINFO_INVALID];
        yield 'a JWT in spaces' => [['Content-Type' => ' application/jwt ; charset=utf-8'], FailureReason::USERINFO_INVALID];
        yield 'a JWT under a header in another case' => [['CONTENT-TYPE' => 'application/jwt'], FailureReason::USERINFO_INVALID];
    }

    /**
     * A signed or encrypted UserInfo response is refused whatever its body, and
     * no other content type is judged.
     *
     * @param  array<string, string>  $headers
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideContentTypes')]
    public function testTheContentTypes(array $headers, ?FailureReason $reason): void
    {
        self::assertSame($reason, $this->answered(FetchResult::fetched(200, $headers, self::BODY)));
    }

    /**
     * Rows of `[bytes, reason]`: bodies under, at and over the cap.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideBodySizes(): iterable
    {
        yield 'one under' => [4095, null];
        yield 'at' => [4096, null];
        yield 'one over' => [4097, FailureReason::FETCH_FAILED];
    }

    /**
     * A body over the configured cap fails; one at it passes.
     *
     * @param  int  $bytes
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideBodySizes')]
    public function testTheCap(int $bytes, ?FailureReason $reason): void
    {
        config()->set('sso.oidc.max_userinfo_bytes', 4096);

        $start = '{"sub":"the-subject","padding":"';
        $end   = '"}';
        $body  = $start . str_repeat('x', $bytes - strlen($start) - strlen($end)) . $end;

        self::assertSame($bytes, strlen($body));
        self::assertSame($reason, $this->answered(self::jsonAnswer($body)));
    }

    /**
     * Rows of `[body]`: bodies that are not a strict JSON object.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedBodies(): iterable
    {
        yield 'empty' => [''];
        yield 'not JSON' => ['the-subject'];
        yield 'cut off' => ['{"sub":"the-subject"'];
        yield 'a compact JWT' => ['header.payload.signature'];
        yield 'a list' => ['["the-subject"]'];
        yield 'a string' => ['"the-subject"'];
        yield 'a number' => ['1'];
        yield 'null' => ['null'];
        yield 'invalid UTF-8' => ["{\"sub\":\"the-subject\",\"name\":\"\xC3\x28\"}"];
        yield 'a repeated subject' => ['{"sub":"the-subject","sub":"the-subject"}'];
        yield 'a subject repeated, the last the honest one' => ['{"sub":"other","sub":"the-subject"}'];
        yield 'a subject repeated under an escape' => ['{"sub":"other","' . chr(92) . 'u0073ub":"the-subject"}'];
        yield 'a repeated email' => ['{"sub":"the-subject","email":"a@example.test","email":"b@example.test"}'];
        yield 'a repeated member in a nested object' => ['{"sub":"the-subject","address":{"a":1,"a":2}}'];
        yield 'nested too deep' => ['{"sub":"the-subject","deep":' . str_repeat('[', 32) . str_repeat(']', 32) . '}'];
    }

    /**
     * A body that is not a strict JSON object is `userinfo_invalid`.
     *
     * @param  string  $body
     * @return void
     */
    #[DataProvider('provideMalformedBodies')]
    public function testAMalformedBodyIsRefused(string $body): void
    {
        self::assertSame(FailureReason::USERINFO_INVALID, $this->answered(self::jsonAnswer($body)));
    }

    /**
     * Rows of `[body]`: bodies whose `sub` is not the subject.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideOtherSubjects(): iterable
    {
        yield 'missing' => ['{"name":"Person"}'];
        yield 'an empty object' => ['{}'];
        yield 'another value' => ['{"sub":"another-subject"}'];
        yield 'empty' => ['{"sub":""}'];
        yield 'null' => ['{"sub":null}'];
        yield 'true' => ['{"sub":true}'];
        yield 'a list' => ['{"sub":["the-subject"]}'];
        yield 'an object' => ['{"sub":{"sub":"the-subject"}}'];
        yield 'a space before' => ['{"sub":" the-subject"}'];
        yield 'a space after' => ['{"sub":"the-subject "}'];
        yield 'a line break after' => ['{"sub":"the-subject\n"}'];
        yield 'another case' => ['{"sub":"THE-SUBJECT"}'];
        yield 'a prefix' => ['{"sub":"the-subject-2"}'];
    }

    /**
     * A `sub` that is not exactly the ID token's is `userinfo_invalid`:
     * missing, another value, another type, whitespace or another case.
     *
     * @param  string  $body
     * @return void
     */
    #[DataProvider('provideOtherSubjects')]
    public function testASubjectThatIsNotExactlyTheTokensIsRefused(string $body): void
    {
        self::assertSame(FailureReason::USERINFO_INVALID, $this->answered(self::jsonAnswer($body)));
    }

    /**
     * Rows of `[subject, body, reason]`: a subject of digits against numbers
     * and strings, and subjects compared byte for byte.
     *
     * @return iterable<string, array{0: string, 1: string, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideExactSubjects(): iterable
    {
        yield 'digits as a string' => ['12345', '{"sub":"12345"}', null];
        yield 'digits as an integer' => ['12345', '{"sub":12345}', FailureReason::USERINFO_INVALID];
        yield 'digits as a float' => ['12345.5', '{"sub":12345.5}', FailureReason::USERINFO_INVALID];
        yield 'many digits as a string' => ['123456789012345678901234567890', '{"sub":"123456789012345678901234567890"}', null];
        yield 'many digits as a number' => ['123456789012345678901234567890', '{"sub":123456789012345678901234567890}', FailureReason::USERINFO_INVALID];
        yield 'spaces kept in both' => [' Subject 1 ', '{"sub":" Subject 1 "}', null];
        yield 'an escape that reads the same' => ['the-subject', '{"s' . chr(92) . 'u0075b":"the-' . chr(92) . 'u0073ubject"}', null];
        yield 'composed against decomposed' => ["caf\u{00E9}", "{\"sub\":\"cafe\u{0301}\"}", FailureReason::USERINFO_INVALID];
    }

    /**
     * The subject is compared byte for byte as a string: a number is never its
     * digits, however large, and no normalisation is applied.
     *
     * @param  string  $subject
     * @param  string  $body
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideExactSubjects')]
    public function testTheSubjectIsComparedExactly(string $subject, string $body, ?FailureReason $reason): void
    {
        self::assertSame($reason, $this->answered(self::jsonAnswer($body), $subject));
    }

    /**
     * Rows of `[members, reason]`: the claims the package reads, by their
     * types.
     *
     * @return iterable<string, array{0: string, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideClaimTypes(): iterable
    {
        yield 'an email' => ['"email":"a@example.test"', null];
        yield 'an email at the longest' => ['"email":"' . str_repeat('a', 320) . '"', null];
        yield 'an email one byte over' => ['"email":"' . str_repeat('a', 321) . '"', FailureReason::USERINFO_INVALID];
        yield 'an empty email' => ['"email":""', FailureReason::USERINFO_INVALID];
        yield 'a numeric email' => ['"email":1', FailureReason::USERINFO_INVALID];
        yield 'a very long number for an email' => ['"email":123456789012345678901234567890', FailureReason::USERINFO_INVALID];
        yield 'a null email' => ['"email":null', FailureReason::USERINFO_INVALID];
        yield 'a list for an email' => ['"email":["a@example.test"]', FailureReason::USERINFO_INVALID];
        yield 'email_verified true' => ['"email_verified":true', null];
        yield 'email_verified false' => ['"email_verified":false', null];
        yield 'the string true' => ['"email_verified":"true"', null];
        yield 'the string false' => ['"email_verified":"false"', null];
        yield 'one' => ['"email_verified":1', null];
        yield 'zero' => ['"email_verified":0', null];
        yield 'a null flag' => ['"email_verified":null', null];
        yield 'an object flag' => ['"email_verified":{"a":true}', null];
        yield 'a list flag' => ['"email_verified":[true]', null];
        yield 'a name' => ['"name":"Person"', null];
        yield 'an empty name' => ['"name":""', null];
        yield 'a numeric name' => ['"name":1', FailureReason::USERINFO_INVALID];
        yield 'a null name' => ['"name":null', FailureReason::USERINFO_INVALID];
        yield 'a given name' => ['"given_name":"Person"', null];
        yield 'a list for a given name' => ['"given_name":["Person"]', FailureReason::USERINFO_INVALID];
        yield 'a family name' => ['"family_name":"Person"', null];
        yield 'an object for a family name' => ['"family_name":{"a":"Person"}', FailureReason::USERINFO_INVALID];
        yield 'all of them' => ['"email":"a@example.test","email_verified":true,"name":"N","given_name":"G","family_name":"F"', null];
        yield 'all but the last' => ['"email":"a@example.test","email_verified":true,"name":"N","given_name":"G","family_name":1', FailureReason::USERINFO_INVALID];
        yield 'a claim the package does not read' => ['"picture":1,"groups":{"a":null}', null];
    }

    /**
     * A claim the package reads with the wrong type is `userinfo_invalid`; a
     * missing one stays unknown, and any other is not judged.
     *
     * @param  string  $members
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideClaimTypes')]
    public function testTheTypesOfTheClaimsRead(string $members, ?FailureReason $reason): void
    {
        self::assertSame($reason, $this->answered(self::jsonAnswer('{"sub":"the-subject",' . $members . '}')));
    }

    /**
     * The claims of an answer not refused are its members, exactly.
     *
     * @return void
     */
    public function testAnswersTheClaims(): void
    {
        $reader = $this->reader();
        $answer = self::jsonAnswer('{"sub":"the-subject","email":"A@Example.test","email_verified":false,"12":"numbered","groups":["a","b"]}');

        self::assertSame(
            ['sub' => self::SUBJECT, 'email' => 'A@Example.test', 'email_verified' => false, 12 => 'numbered', 'groups' => ['a', 'b']],
            $reader->claims($answer, self::idToken()),
        );
    }

    /**
     * The claims of an answer keep a number a number, however large, never its
     * digits.
     *
     * @return void
     */
    public function testAnswersALargeNumberAsANumber(): void
    {
        $answer = self::jsonAnswer('{"sub":"the-subject","employee":99999999999999999999}');

        self::assertSame(['sub' => self::SUBJECT, 'employee' => 1.0E+20], $this->reader()->claims($answer, self::idToken()));
    }

    /**
     * Rows of `[answer]`: answers that hold no claims.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult}>
     */
    public static function provideRefusedAnswers(): iterable
    {
        yield 'failed' => [FetchResult::failed()];
        yield 'another subject' => [self::jsonAnswer('{"sub":"another-subject"}')];
        yield 'malformed' => [self::jsonAnswer('nope')];
    }

    /**
     * Asking for the claims of an answer that is refused is the caller's
     * mistake.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @return void
     */
    #[DataProvider('provideRefusedAnswers')]
    public function testARefusedAnswerHoldsNoClaims(FetchResult $answer): void
    {
        $this->expectExceptionObject(new \LogicException('Only an answer that is not refused holds claims.'));

        $this->reader()->claims($answer, self::idToken());
    }

    /**
     * Rows of `[header, code]`: what is read of `WWW-Authenticate`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideChallenges(): iterable
    {
        yield 'invalid_token' => ['Bearer error="invalid_token"', 'invalid_token'];
        yield 'invalid_request' => ['Bearer error="invalid_request"', 'invalid_request'];
        yield 'insufficient_scope' => ['Bearer error="insufficient_scope"', 'insufficient_scope'];
        yield 'after a realm' => ['Bearer realm="example", error="invalid_token"', 'invalid_token'];
        yield 'before a description' => ['Bearer error="invalid_token", error_description="The token expired"', 'invalid_token'];
        yield 'not quoted' => ['Bearer error=invalid_token', 'invalid_token'];
        yield 'the name in another case' => ['Bearer ERROR="invalid_token"', 'invalid_token'];
        yield 'spaces around the equals sign' => ['Bearer error = "invalid_token"', 'invalid_token'];
        yield 'after a description quoting a code' => ['Bearer error_description="error=invalid_token", error="invalid_request"', 'invalid_request'];
        yield 'a description quoting a code alone' => ['Bearer error_description="error=\"invalid_token\""', null];
        yield 'another parameter ending in the name' => ['Bearer xerror="invalid_token"', null];
        yield 'an extension code' => ['Bearer error="vendor_code"', null];
        yield 'a code in another case' => ['Bearer error="INVALID_TOKEN"', null];
        yield 'prose' => ['Bearer error="the token is not valid"', null];
        yield 'the first error decides' => ['Bearer error="nonsense", error="invalid_token"', null];
        yield 'an empty code' => ['Bearer error=""', null];
        yield 'no value' => ['Bearer error=', null];
        yield 'no parameters' => ['Bearer', null];
        yield 'an empty header' => ['', null];
        yield 'no header' => [null, null];
    }

    /**
     * Only one of RFC 6750's bearer token error codes is read from
     * `WWW-Authenticate`: a description, prose and any other code never are.
     *
     * @param  ?string  $header
     * @param  ?string  $code
     * @return void
     */
    #[DataProvider('provideChallenges')]
    public function testReadsOnlyTheErrorCode(?string $header, ?string $code): void
    {
        $headers = $header === null ? [] : ['WWW-Authenticate' => $header];

        self::assertSame($code, $this->reader()->providerError(FetchResult::fetched(401, $headers, '')));
    }

    /**
     * Answer the endpoint with the response, send the request, and say how the
     * answer is judged against an ID token of the subject.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  string  $subject
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function answered(FetchResult $response, string $subject = self::SUBJECT): ?FailureReason
    {
        $this->fetcher->respond(self::ENDPOINT, $response);

        $reader = $this->reader();

        return $reader->refusal($reader->fetch(self::readerOptions(), self::tokens()), self::idToken($subject));
    }

    /**
     * The reader, resolved from the container.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\UserInfoReader
     */
    private function reader(): UserInfoReader
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(UserInfoReader::class);
    }

    /**
     * The options of a connection that fetches UserInfo.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions
     */
    private static function readerOptions(): OidcOptions
    {
        return OidcOptions::of(new IdentifiedConnection('c1', settings: ['fetch_userinfo' => true, 'userinfo_endpoint' => self::ENDPOINT]));
    }

    /**
     * The token endpoint's answer.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse
     */
    private static function tokens(): TokenResponse
    {
        return new TokenResponse('header.payload.signature', self::ACCESS_TOKEN);
    }

    /**
     * A validated ID token of the subject.
     *
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken
     */
    private static function idToken(string $subject = self::SUBJECT): ValidatedIdToken
    {
        return new ValidatedIdToken(self::ISSUER, $subject, ['iss' => self::ISSUER, 'sub' => $subject]);
    }

    /**
     * A `200` JSON answer holding the body as it is.
     *
     * @param  string  $body
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    private static function jsonAnswer(string $body): FetchResult
    {
        return FetchResult::fetched(200, ['Content-Type' => self::JSON_TYPE], $body);
    }
}
