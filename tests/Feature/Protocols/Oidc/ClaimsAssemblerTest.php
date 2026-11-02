<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\AttributeMapping;
use SineMacula\Laravel\Sso\Connections\MappingLimits;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClaimsAssembler;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Concerns\CapturesLogs;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for assembling what an OpenID Connect completion verified
 * (SSO-7.5, SSO-7.7, SSO-8.1, SSO-2.10): UserInfo off makes no fetch; on and
 * refused fails closed with the exact reason, logging an error's code alone;
 * UserInfo never changes the issuer, the subject or an authentication claim; it
 * wins for mapped attributes but for the email, which comes from one source;
 * the full claims pinned; and a claim that does not fit refused, never thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClaimsAssembler::class)]
final class ClaimsAssemblerTest extends TestCase
{
    use CapturesLogs;

    /** @var string The connection's id. */
    private const string CONNECTION_ID = '01jbexampleconnection00000';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Cq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The connection's issuer. */
    private const string ISSUER = 'https://op.example.test';

    /** @var string The connection's UserInfo endpoint. */
    private const string ENDPOINT = 'https://op.example.test/userinfo';

    /** @var string The subject of the ID token, exactly as received. */
    private const string SUBJECT = ' The Subject 1 ';

    /** @var string The access token the token endpoint answered. */
    private const string ACCESS_TOKEN = 'the-access-token';

    /** @var int 2026-11-01T09:29:00Z. */
    private const int AUTHENTICATED_AT = 1793525340;

    /** @var int The last second a result can store. */
    private const int LATEST = 253402300799;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher UserInfo is requested through. */
    private FakeFetcher $fetcher;

    /**
     * Bind the fake fetcher and capture logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Fetcher::class, $this->fetcher);

        $this->captureLogs();
    }

    /**
     * With UserInfo off nothing is fetched, even with an endpoint named, and
     * the claims come from the ID token alone.
     *
     * @return void
     */
    public function testUserInfoOffMakesNoFetch(): void
    {
        $claims = $this->verifiedClaims($this->assembleWithoutUserInfo(['email' => 'token@example.test', 'email_verified' => true, 'name' => 'Token Name']));

        $this->fetcher->assertNothingFetched();

        self::assertSame(['name' => 'Token Name', 'email' => 'token@example.test'], $claims->attributes);
        self::assertSame(['email' => 'token@example.test', 'verified' => true, 'source' => 'id_token'], $claims->assertedEmail?->toArray());
    }

    /**
     * With UserInfo on, one request is made, carrying the access token.
     *
     * @return void
     */
    public function testUserInfoOnMakesOneRequest(): void
    {
        $this->verifiedClaims($this->assembleWithUserInfo([], self::userInfo(['sub' => self::SUBJECT])));

        $requests = $this->fetcher->requests();

        self::assertCount(1, $requests);
        self::assertSame(self::ENDPOINT, $requests[0]->url);
        self::assertSame(self::ACCESS_TOKEN, $requests[0]->credentials?->secret());
    }

    /**
     * Every part of the claims is pinned, from an ID token and a UserInfo
     * response each with everything: the identity and the authentication
     * context from the ID token, the attributes with UserInfo over them and no
     * protocol value, the email from the ID token, and no replay record.
     *
     * @return void
     */
    public function testTheWholeOfTheClaimsIsPinned(): void
    {
        $completion = $this->assembleWithUserInfo([
            'nbf'            => self::AUTHENTICATED_AT,
            'jti'            => 'the-jti',
            'auth_time'      => self::AUTHENTICATED_AT + 0.5,
            'nonce'          => 'the-nonce',
            'acr'            => 'urn:example:acr',
            'amr'            => ['pwd', 'otp'],
            'azp'            => 'the-client',
            'at_hash'        => 'the-at-hash',
            'c_hash'         => 'the-c-hash',
            's_hash'         => 'the-s-hash',
            'sid'            => 'the-session',
            'email'          => 'Token@Example.test',
            'email_verified' => true,
            'name'           => 'Token Name',
            'locale'         => 'en-GB',
        ], self::userInfo([
            'sub'            => self::SUBJECT,
            'name'           => 'UserInfo Name',
            'picture'        => 'https://cdn.example.test/picture',
            'email'          => 'userinfo@example.test',
            'email_verified' => false,
            'iss'            => 'https://attacker.example.test',
            'aud'            => 'another-client',
            'exp'            => 1,
            'iat'            => 1,
            'nbf'            => 1,
            'jti'            => 'another-jti',
            'auth_time'      => 1,
            'nonce'          => 'another-nonce',
            'acr'            => 'urn:example:another',
            'amr'            => ['none'],
            'azp'            => 'another-client',
            'at_hash'        => 'another',
            'c_hash'         => 'another',
            's_hash'         => 'another',
            'sid'            => 'another-session',
            'access_token'   => 'a-token-in-userinfo',
            'id_token'       => 'a-token-in-userinfo',
            'refresh_token'  => 'a-token-in-userinfo',
            'code'           => 'a-code-in-userinfo',
            'state'          => 'a-state-in-userinfo',
            'client_id'      => 'another-client',
        ]));

        self::assertTrue($completion->isVerified());
        self::assertNull($completion->reason);
        self::assertNull($completion->replay);

        self::assertSame([
            'issuer'         => self::ISSUER,
            'subject'        => self::SUBJECT,
            'name_id_format' => null,
            'attributes'     => [
                'name'    => 'UserInfo Name',
                'locale'  => 'en-GB',
                'picture' => 'https://cdn.example.test/picture',
                'email'   => 'Token@Example.test',
            ],
            'authentication_context' => [
                'authenticated_at'          => '2026-11-01T09:29:00.500000Z',
                'methods'                   => ['pwd', 'otp'],
                'context_class'             => 'urn:example:acr',
                'provider_session_id'       => 'the-session',
                'provider_session_deadline' => null,
            ],
            'linking_email'  => ['email' => 'Token@Example.test', 'source' => 'id_token', 'organization' => null],
            'asserted_email' => ['email' => 'Token@Example.test', 'verified' => true, 'source' => 'id_token'],
        ], self::described($this->verifiedClaims($completion)));
    }

    /**
     * An ID token that states no authentication context states none, and a
     * UserInfo response stating one changes nothing: not the context, the
     * issuer or the subject, and no linking email without a pair.
     *
     * @return void
     */
    public function testUserInfoNeverStatesTheAuthenticationContext(): void
    {
        $claims = $this->verifiedClaims($this->assembleWithUserInfo([], self::userInfo([
            'sub'       => self::SUBJECT,
            'iss'       => 'https://attacker.example.test',
            'auth_time' => self::AUTHENTICATED_AT,
            'acr'       => 'urn:example:another',
            'amr'       => ['pwd'],
            'sid'       => 'another-session',
        ])));

        self::assertSame([
            'issuer'                 => self::ISSUER,
            'subject'                => self::SUBJECT,
            'name_id_format'         => null,
            'attributes'             => [],
            'authentication_context' => [
                'authenticated_at'          => null,
                'methods'                   => [],
                'context_class'             => null,
                'provider_session_id'       => null,
                'provider_session_deadline' => null,
            ],
            'linking_email'  => null,
            'asserted_email' => null,
        ], self::described($claims));
    }

    /**
     * Mapped through the connection's mapping, UserInfo wins for a claim both
     * state, the ID token's stands for one only it states, and the email is the
     * pair's.
     *
     * @return void
     */
    public function testTheMappedAttributesHaveUserInfoWinning(): void
    {
        $claims = $this->verifiedClaims($this->assembleWithUserInfo(
            ['email' => 'token@example.test', 'name' => 'Token Name', 'given_name' => 'Token', 'groups' => ['token-group']],
            self::userInfo(['sub' => self::SUBJECT, 'email' => 'userinfo@example.test', 'email_verified' => true, 'name' => 'UserInfo Name', 'family_name' => 'Info']),
        ));

        /** @var \Illuminate\Foundation\Application $app */
        $app     = $this->app;
        $mapping = AttributeMapping::fromArray('oidc', AttributeMapping::defaults('oidc'), $app->make(MappingLimits::class));

        self::assertSame([
            'email'        => 'token@example.test',
            'given_name'   => 'Token',
            'family_name'  => 'Info',
            'display_name' => 'UserInfo Name',
            'groups'       => ['token-group'],
        ], $mapping->map($claims->attributes));
    }

    /**
     * Rows of `[ID token, UserInfo, email attribute, pair]`: the email of the
     * attributes is always the pair's, or there is none.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: ?string, 3: ?array<string, mixed>}>
     */
    public static function provideEmails(): iterable
    {
        yield 'neither' => [[], [], null, null];
        yield 'the ID token only' => [
            ['email' => 'token@example.test', 'email_verified' => false],
            [],
            'token@example.test',
            ['email' => 'token@example.test', 'verified' => false, 'source' => 'id_token'],
        ];
        yield 'UserInfo only' => [
            [],
            ['email' => 'userinfo@example.test', 'email_verified' => false],
            'userinfo@example.test',
            ['email' => 'userinfo@example.test', 'verified' => false, 'source' => 'userinfo'],
        ];
        yield 'both differing' => [
            ['email' => 'token@example.test'],
            ['email' => 'userinfo@example.test', 'email_verified' => true],
            'token@example.test',
            ['email' => 'token@example.test', 'verified' => null, 'source' => 'id_token'],
        ];
        yield 'the flag alone in the ID token' => [
            ['email_verified' => true],
            ['email' => 'userinfo@example.test'],
            'userinfo@example.test',
            ['email' => 'userinfo@example.test', 'verified' => null, 'source' => 'userinfo'],
        ];
    }

    /**
     * The attributes' email and the asserted pair never disagree, and
     * `email_verified` is never an attribute.
     *
     * @param  array<string, mixed>  $idToken
     * @param  array<string, mixed>  $userInfo
     * @param  ?string  $attribute
     * @param  ?array<string, mixed>  $pair
     * @return void
     */
    #[DataProvider('provideEmails')]
    public function testTheAttributesEmailIsThePairs(array $idToken, array $userInfo, ?string $attribute, ?array $pair): void
    {
        $claims = $this->verifiedClaims($this->assembleWithUserInfo($idToken, self::userInfo(['sub' => self::SUBJECT, ...$userInfo])));

        self::assertSame($attribute === null ? [] : ['email' => $attribute], $claims->attributes);
        self::assertSame($pair, $claims->assertedEmail?->toArray());
    }

    /**
     * Rows of `[ID token, UserInfo, linking email]`: when the pair gives a
     * linking email.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: ?array<string, mixed>}>
     */
    public static function provideLinkingEmails(): iterable
    {
        yield 'the ID token, verified' => [
            ['email' => 'a@example.test', 'email_verified' => true],
            [],
            ['email' => 'a@example.test', 'source' => 'id_token', 'organization' => null],
        ];
        yield 'UserInfo, verified' => [
            [],
            ['email' => 'a@example.test', 'email_verified' => true],
            ['email' => 'a@example.test', 'source' => 'userinfo', 'organization' => null],
        ];
        yield 'not verified' => [['email' => 'a@example.test', 'email_verified' => false], [], null];
        yield 'unknown' => [['email' => 'a@example.test'], [], null];
        yield 'verified only in the other source' => [['email' => 'a@example.test'], ['email' => 'a@example.test', 'email_verified' => true], null];
        yield 'no @' => [['email' => 'not-an-address', 'email_verified' => true], [], null];
        yield 'two @' => [['email' => 'a@b@example.test', 'email_verified' => true], [], null];
        yield 'no local part' => [[], ['email' => '@example.test', 'email_verified' => true], null];
        yield 'no domain' => [[], ['email' => 'a@', 'email_verified' => true], null];
    }

    /**
     * A linking email needs the pair's own `email_verified` exactly true and a
     * well formed email; the asserted pair stays whatever it says.
     *
     * @param  array<string, mixed>  $idToken
     * @param  array<string, mixed>  $userInfo
     * @param  ?array<string, mixed>  $linking
     * @return void
     */
    #[DataProvider('provideLinkingEmails')]
    public function testTheLinkingEmail(array $idToken, array $userInfo, ?array $linking): void
    {
        $claims = $this->verifiedClaims($this->assembleWithUserInfo($idToken, self::userInfo(['sub' => self::SUBJECT, ...$userInfo])));

        self::assertSame($linking, $claims->linkingEmail?->toArray());
        self::assertNotNull($claims->assertedEmail);
    }

    /**
     * Rows of `[auth_time, stored]`: the instants, at full precision.
     *
     * @return iterable<string, array{0: float|int, 1: string}>
     */
    public static function provideAuthenticationTimes(): iterable
    {
        yield 'a whole second' => [self::AUTHENTICATED_AT, '2026-11-01T09:29:00.000000Z'];
        yield 'a whole second as a float' => [(float) self::AUTHENTICATED_AT, '2026-11-01T09:29:00.000000Z'];
        yield 'half a second' => [self::AUTHENTICATED_AT + 0.5, '2026-11-01T09:29:00.500000Z'];
        yield 'to the microsecond' => [self::AUTHENTICATED_AT + 0.123456, '2026-11-01T09:29:00.123456Z'];
        yield 'the epoch' => [0, '1970-01-01T00:00:00.000000Z'];
        yield 'the last second a result can store' => [self::LATEST, '9999-12-31T23:59:59.000000Z'];
    }

    /**
     * `auth_time` is read at full precision, in UTC, and what is stored reads
     * back.
     *
     * @param  float|int  $authTime
     * @param  string  $stored
     * @return void
     */
    #[DataProvider('provideAuthenticationTimes')]
    public function testTheAuthenticationTime(float|int $authTime, string $stored): void
    {
        $context = $this->verifiedClaims($this->assembleWithoutUserInfo(['auth_time' => $authTime]))->authenticationContext;

        self::assertSame($stored, $context->toArray()['authenticated_at']);
        self::assertSame('UTC', $context->authenticatedAt?->getTimezone()->getName());
        self::assertSame($stored, $context::restore($context->toArray())->toArray()['authenticated_at']);
    }

    /**
     * An `auth_time` that says nothing states nothing, and `iat` never stands
     * in for it.
     *
     * @return void
     */
    public function testNoAuthenticationTimeIsNone(): void
    {
        self::assertNull($this->verifiedClaims($this->assembleWithoutUserInfo())->authenticationContext->authenticatedAt);
    }

    /**
     * Rows of `[claims]`: an ID token's claims at the bounds of what fits.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideFittingClaims(): iterable
    {
        yield 'no methods' => [['amr' => []]];
        yield 'as many methods as are kept, each at the longest' => [['amr' => array_fill(0, 32, str_repeat('m', 255))]];
        yield 'a one-byte method' => [['amr' => ['m']]];
        yield 'the longest class' => [['acr' => str_repeat('c', 1024)]];
        yield 'a one-byte class' => [['acr' => 'c']];
        yield 'the longest session' => [['sid' => str_repeat('s', 1024)]];
        yield 'a one-byte session' => [['sid' => 's']];
        yield 'the longest email' => [['email' => str_repeat('e', 320)]];
    }

    /**
     * Claims at the bounds of what a result holds are verified.
     *
     * @param  array<string, mixed>  $claims
     * @return void
     */
    #[DataProvider('provideFittingClaims')]
    public function testClaimsAtTheBoundsAreVerified(array $claims): void
    {
        self::assertTrue($this->assembleWithoutUserInfo($claims)->isVerified());
    }

    /**
     * The longest issuer and subject a result holds are verified.
     *
     * @return void
     */
    public function testTheLongestIssuerAndSubjectAreVerified(): void
    {
        $issuer  = str_repeat('i', 1024);
        $subject = str_repeat('s', 1024);
        $claims  = $this->verifiedClaims($this->assembleToken(new ValidatedIdToken($issuer, $subject, ['iss' => $issuer, 'sub' => $subject]), self::settings(false)));

        self::assertSame($issuer, $claims->issuer);
        self::assertSame($subject, $claims->subject);
    }

    /**
     * Rows of `[claims]`: an ID token's claims that do not fit what a result
     * holds.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideUnfitClaims(): iterable
    {
        yield 'amr a string' => [['amr' => 'pwd']];
        yield 'amr a map' => [['amr' => ['a' => 'pwd']]];
        yield 'amr null' => [['amr' => null]];
        yield 'amr holding a number' => [['amr' => ['pwd', 1]]];
        yield 'amr holding an empty string' => [['amr' => ['']]];
        yield 'amr holding one too long' => [['amr' => [str_repeat('m', 256)]]];
        yield 'amr one too many' => [['amr' => array_fill(0, 33, 'pwd')]];
        yield 'acr a number' => [['acr' => 1]];
        yield 'acr null' => [['acr' => null]];
        yield 'acr empty' => [['acr' => '']];
        yield 'acr too long' => [['acr' => str_repeat('c', 1025)]];
        yield 'sid a number' => [['sid' => 1]];
        yield 'sid null' => [['sid' => null]];
        yield 'sid empty' => [['sid' => '']];
        yield 'sid too long' => [['sid' => str_repeat('s', 1025)]];
        yield 'auth_time a numeric string' => [['auth_time' => '1793525340']];
        yield 'auth_time a boolean' => [['auth_time' => true]];
        yield 'auth_time null' => [['auth_time' => null]];
        yield 'auth_time before the epoch' => [['auth_time' => -1]];
        yield 'auth_time just before the epoch' => [['auth_time' => -0.5]];
        yield 'auth_time after what a result can store' => [['auth_time' => self::LATEST + 1]];
        yield 'auth_time infinite' => [['auth_time' => INF]];
        yield 'an email of the wrong type' => [['email' => 1]];
        yield 'an empty email' => [['email' => '']];
        yield 'an email too long' => [['email' => str_repeat('e', 321)]];
        yield 'email_verified a string' => [['email' => 'a@example.test', 'email_verified' => 'true']];
        yield 'email_verified a string with no email' => [['email_verified' => 'true']];
    }

    /**
     * A claim that does not fit is `id_token_invalid`, never an exception.
     *
     * @param  array<string, mixed>  $claims
     * @return void
     */
    #[DataProvider('provideUnfitClaims')]
    public function testAClaimThatDoesNotFitIsRefused(array $claims): void
    {
        $completion = $this->assembleWithoutUserInfo($claims);

        self::assertSame(FailureReason::ID_TOKEN_INVALID, $completion->reason);
        self::assertNull($completion->claims);
    }

    /**
     * Rows of `[issuer, subject]`: an issuer or subject longer than a result
     * holds.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideTooLongIdentities(): iterable
    {
        yield 'the issuer' => [str_repeat('i', 1025), 's'];
        yield 'the subject' => ['i', str_repeat('s', 1025)];
    }

    /**
     * An issuer or subject longer than a result holds is `id_token_invalid`,
     * never an exception.
     *
     * @param  string  $issuer
     * @param  string  $subject
     * @return void
     */
    #[DataProvider('provideTooLongIdentities')]
    public function testAnIdentityThatDoesNotFitIsRefused(string $issuer, string $subject): void
    {
        $completion = $this->assembleToken(new ValidatedIdToken($issuer, $subject, ['iss' => $issuer, 'sub' => $subject]), self::settings(false));

        self::assertSame(FailureReason::ID_TOKEN_INVALID, $completion->reason);
    }

    /**
     * UserInfo is read first: a token whose claims do not fit is refused only
     * once it passed, and a UserInfo refusal is what is answered when both are
     * refused.
     *
     * @return void
     */
    public function testUserInfoIsReadFirst(): void
    {
        self::assertSame(FailureReason::FETCH_FAILED, $this->assembleWithUserInfo(['acr' => 1], FetchResult::failed())->reason);
        self::assertCount(1, $this->fetcher->requests());
        self::assertSame(FailureReason::ID_TOKEN_INVALID, $this->assembleWithUserInfo(['acr' => 1], self::userInfo(['sub' => self::SUBJECT]))->reason);
    }

    /**
     * Rows of `[answer, reason]`: answers that refuse the completion.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'refused' => [FetchResult::refused(), FailureReason::FETCH_REFUSED];
        yield 'failed' => [FetchResult::failed(), FailureReason::FETCH_FAILED];
        yield 'a 401' => [FetchResult::fetched(401, [], ''), FailureReason::PROVIDER_ERROR];
        yield 'a 403' => [FetchResult::fetched(403, [], ''), FailureReason::PROVIDER_ERROR];
        yield 'a 404' => [FetchResult::fetched(404, [], ''), FailureReason::FETCH_FAILED];
        yield 'a 500' => [FetchResult::fetched(500, [], ''), FailureReason::FETCH_FAILED];
        yield 'a JWT' => [FetchResult::fetched(200, ['Content-Type' => 'application/jwt'], 'header.payload.signature'), FailureReason::USERINFO_INVALID];
        yield 'not an object' => [FetchResult::fetched(200, [], '[]'), FailureReason::USERINFO_INVALID];
        yield 'another subject' => [FetchResult::fetched(200, [], '{"sub":"another-subject"}'), FailureReason::USERINFO_INVALID];
        yield 'no subject' => [FetchResult::fetched(200, [], '{"email":"a@example.test"}'), FailureReason::USERINFO_INVALID];
        yield 'a string flag' => [FetchResult::fetched(200, [], '{"sub":" The Subject 1 ","email_verified":"true"}'), FailureReason::USERINFO_INVALID];
    }

    /**
     * With UserInfo on, a refusal fails the completion with its exact reason,
     * with nothing of the ID token's claims going on without it.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testUserInfoRefusedFailsClosed(FetchResult $answer, FailureReason $reason): void
    {
        $completion = $this->assembleWithUserInfo(['email' => 'token@example.test', 'email_verified' => true], $answer);

        self::assertTrue($completion->isRefused());
        self::assertSame($reason, $completion->reason);
        self::assertNull($completion->claims);
        self::assertNull($completion->replay);
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * Rows of `[status, header, logged]`: what a provider's error logs.
     *
     * @return iterable<string, array{0: int, 1: array<string, string>, 2: string}>
     */
    public static function provideProviderErrors(): iterable
    {
        yield 'a 401 with a code' => [401, ['WWW-Authenticate' => 'Bearer error="invalid_token", error_description="described"'], 'invalid_token'];
        yield 'a 403 with a code' => [403, ['WWW-Authenticate' => 'Bearer error="insufficient_scope"'], 'insufficient_scope'];
        yield 'another code' => [401, ['WWW-Authenticate' => 'Bearer error="vendor_code"'], '[unrecognized]'];
        yield 'no code' => [401, ['WWW-Authenticate' => 'Bearer realm="example"'], '[unrecognized]'];
        yield 'no header' => [401, [], '[unrecognized]'];
    }

    /**
     * A provider's error logs its bearer token error code alone, with the
     * connection and the request's reference, as one notice.
     *
     * @param  int  $status
     * @param  array<string, string>  $headers
     * @param  string  $logged
     * @return void
     */
    #[DataProvider('provideProviderErrors')]
    public function testAProvidersErrorIsLoggedByItsCodeAlone(int $status, array $headers, string $logged): void
    {
        $this->assembleWithUserInfo([], FetchResult::fetched($status, $headers, '{"error":"invalid_token","error_description":"described"}'));

        self::assertSame([[
            'channel' => 'sso_capture',
            'level'   => 'notice',
            'message' => 'sso.oidc.userinfo_error',
            'context' => ['connection_id' => self::CONNECTION_ID, 'request_reference' => self::REFERENCE, 'error' => $logged],
        ]], $this->capturedLogRecords());
    }

    /**
     * Rows of `[answer]`: refusals that are not a provider's error, and a pass.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult}>
     */
    public static function provideQuietAnswers(): iterable
    {
        yield 'refused' => [FetchResult::refused()];
        yield 'failed' => [FetchResult::failed()];
        yield 'a 500' => [FetchResult::fetched(500, ['WWW-Authenticate' => 'Bearer error="invalid_token"'], '')];
        yield 'malformed' => [FetchResult::fetched(200, ['WWW-Authenticate' => 'Bearer error="invalid_token"'], 'nope')];
        yield 'passing' => [FetchResult::fetched(200, [], '{"sub":" The Subject 1 "}')];
    }

    /**
     * Nothing but a provider's error is logged.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @return void
     */
    #[DataProvider('provideQuietAnswers')]
    public function testNothingElseIsLogged(FetchResult $answer): void
    {
        $this->assembleWithUserInfo([], $answer);

        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * A claim named by digits keeps its name when UserInfo is laid over the ID
     * token and when the email is set, so a mapping can read it.
     *
     * @return void
     */
    public function testAClaimNamedByDigitsKeepsItsName(): void
    {
        $members = ['iss' => self::ISSUER, 'sub' => self::SUBJECT, 'email' => 'a@example.test', 12345 => 'from-the-token', 678 => 'overlaid'];
        $idToken = new ValidatedIdToken(self::ISSUER, self::SUBJECT, $members);
        $answer  = FetchResult::fetched(200, [], '{"sub":" The Subject 1 ","678":"from-userinfo","90":"new"}');
        $claims  = $this->verifiedClaims($this->assembleToken($idToken, self::settings(true), $answer));

        self::assertSame([12345 => 'from-the-token', 678 => 'from-userinfo', 90 => 'new', 'email' => 'a@example.test'], $claims->attributes);
    }

    /**
     * The assembly reports no event of its own, verified or refused: the
     * pipeline reports the completion.
     *
     * @return void
     */
    public function testReportsNoEvent(): void
    {
        $seen = new \ArrayObject;

        Event::listen('*', static function (string $name) use ($seen): void {

            if (!str_starts_with($name, 'SineMacula\Laravel\Sso\\')) {
                return;
            }

            $seen->append($name);
        });

        $this->assembleWithUserInfo([], self::userInfo(['sub' => self::SUBJECT]));
        $this->assembleWithUserInfo([], FetchResult::fetched(401, [], ''));
        $this->assembleWithoutUserInfo();

        self::assertSame([], $seen->getArrayCopy());
    }

    /**
     * Assemble the claims of an ID token with the claims given, with UserInfo
     * off.
     *
     * @param  array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function assembleWithoutUserInfo(array $claims = []): Completion
    {
        return $this->assembleToken(self::idToken($claims), self::settings(false));
    }

    /**
     * Assemble the claims of an ID token with the claims given, with UserInfo
     * on and answered as given.
     *
     * @param  array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function assembleWithUserInfo(array $claims, FetchResult $answer): Completion
    {
        return $this->assembleToken(self::idToken($claims), self::settings(true), $answer);
    }

    /**
     * Assemble the claims of the ID token under the settings, answering
     * UserInfo as given.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken  $idToken
     * @param  array<string, mixed>  $settings
     * @param  ?\SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function assembleToken(ValidatedIdToken $idToken, array $settings, ?FetchResult $answer = null): Completion
    {
        if ($answer !== null) {
            $this->fetcher->respond(self::ENDPOINT, $answer);
        }

        /** @var \Illuminate\Foundation\Application $app */
        $app        = $this->app;
        $connection = new IdentifiedConnection(self::CONNECTION_ID, settings: $settings);
        $consumed   = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(self::REFERENCE), CarbonImmutable::parse('2026-11-01T09:28:00Z'));
        $tokens     = new TokenResponse('header.payload.signature', self::ACCESS_TOKEN);

        return $app->make(ClaimsAssembler::class)->assemble($connection, OidcOptions::of($connection), $idToken, $tokens, $consumed);
    }

    /**
     * The claims of a verified completion.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Completion  $completion
     * @return \SineMacula\Laravel\Sso\Results\VerifiedClaims
     */
    private function verifiedClaims(Completion $completion): VerifiedClaims
    {
        self::assertNull($completion->reason);
        self::assertNotNull($completion->claims);

        return $completion->claims;
    }

    /**
     * Everything the claims hold, as a test pins it.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @return array<string, mixed>
     */
    private static function described(VerifiedClaims $claims): array
    {
        return [
            'issuer'                 => $claims->issuer,
            'subject'                => $claims->subject,
            'name_id_format'         => $claims->nameIdFormat,
            'attributes'             => $claims->attributes,
            'authentication_context' => $claims->authenticationContext->toArray(),
            'linking_email'          => $claims->linkingEmail?->toArray(),
            'asserted_email'         => $claims->assertedEmail?->toArray(),
        ];
    }

    /**
     * The connection's settings, with UserInfo on or off, its endpoint named
     * either way.
     *
     * @param  bool  $fetches
     * @return array<string, mixed>
     */
    private static function settings(bool $fetches): array
    {
        return ['fetch_userinfo' => $fetches, 'userinfo_endpoint' => self::ENDPOINT];
    }

    /**
     * A validated ID token: the claims every token has, and those given.
     *
     * @param  array<string, mixed>  $claims
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken
     */
    private static function idToken(array $claims): ValidatedIdToken
    {
        return new ValidatedIdToken(self::ISSUER, self::SUBJECT, [
            'iss' => self::ISSUER,
            'sub' => self::SUBJECT,
            'aud' => 'the-client',
            'exp' => self::AUTHENTICATED_AT + 300,
            'iat' => self::AUTHENTICATED_AT,
            ...$claims,
        ]);
    }

    /**
     * A `200` UserInfo answer holding the members given.
     *
     * @param  array<string, mixed>  $members
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    private static function userInfo(array $members): FetchResult
    {
        return FakeTokenEndpoint::json(200, $members);
    }
}
