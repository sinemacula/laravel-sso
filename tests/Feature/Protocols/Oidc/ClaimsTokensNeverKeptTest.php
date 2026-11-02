<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\ResultBuilder;
use SineMacula\Laravel\Sso\Connections\AttributeMapping;
use SineMacula\Laravel\Sso\Contracts\Clock;
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
use SineMacula\Laravel\Sso\Protocols\Oidc\UserInfoReader;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * The provider's tokens and what it said are used only during the completion
 * and never kept (SSO-7.6, SSO-5.7): for verified and refused assemblies alike,
 * no log, no dump and no serialised result holds the access token, the ID
 * token, the UserInfo body or an error description, and no JSON form of the
 * claims holds the email.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClaimsAssembler::class)]
#[CoversClass(UserInfoReader::class)]
final class ClaimsTokensNeverKeptTest extends TestCase
{
    use CapturesLogs, DumpsValues, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The connection's UserInfo endpoint. */
    private const string ENDPOINT = 'https://op.example.test/userinfo';

    /** @var string The connection's issuer. */
    private const string ISSUER = 'https://op.example.test';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Dq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The subject of the ID token. */
    private const string SUBJECT = 'the-subject';

    /** @var string The access token the token endpoint answered. */
    private const string ACCESS_TOKEN = 'the-access-token-never-kept';

    /** @var string The ID token the token endpoint answered. */
    private const string ID_TOKEN = 'the-id-token.never.kept';

    /** @var string A refresh token a provider put in UserInfo. */
    private const string REFRESH_TOKEN = 'the-refresh-token-never-kept';

    /** @var string What a provider's error description holds. */
    private const string DESCRIPTION = 'the-description-never-kept';

    /** @var string The email both sources assert. */
    private const string EMAIL = 'the-email@example.test';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher UserInfo is requested through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and the fake fetcher, create the tables, and capture
     * logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Fetcher::class, $this->fetcher);

        $this->createConnectionTables();
        $this->createDomainsTable();
        $this->createFlowTables();

        $this->captureLogs();

        config()->set('sso.features.domain_linking', true);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropFlowTables();
        $this->dropDomainsTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A verified assembly, whose UserInfo answer echoes the tokens as claims,
     * logs nothing, and neither its completion, its result nor what it was
     * given shows a token or the body.
     *
     * @return void
     */
    public function testAVerifiedAssemblyKeepsNothing(): void
    {
        $body = self::body([
            'sub'            => self::SUBJECT,
            'email'          => self::EMAIL,
            'email_verified' => true,
            'name'           => 'A Name',
            'access_token'   => self::ACCESS_TOKEN,
            'id_token'       => self::ID_TOKEN,
            'refresh_token'  => self::REFRESH_TOKEN,
        ]);

        $completion = $this->assemble(FetchResult::fetched(200, ['Content-Type' => 'application/json'], $body));

        self::assertTrue($completion->isVerified());
        self::assertSame([], $this->capturedLogRecords());

        $needles = [self::ACCESS_TOKEN, self::ID_TOKEN, self::REFRESH_TOKEN, $body];

        $this->assertNoDumpShows($completion, $needles);
        $this->assertNoDumpShows($completion->claims, $needles);
        $this->assertNoFetchedRequestShows($needles);

        self::assertInstanceOf(VerifiedClaims::class, $completion->claims);

        $json = (string) json_encode($completion->claims);

        self::assertStringContainsString('"asserted_email":{"source":"userinfo","verified":true}', $json);
        self::assertStringContainsString('"linking_email":{"email":"[redacted]","source":"userinfo","organization":null}', $json);

        foreach ([...$needles, self::EMAIL] as $needle) {
            self::assertStringNotContainsString($needle, $json);
        }

        $result = $this->verifiedResult($completion->claims);

        foreach ([serialize($result), (string) json_encode($result), (string) json_encode($result->toArray())] as $form) {
            foreach ($needles as $needle) {
                self::assertStringNotContainsString($needle, $form);
            }
        }
    }

    /**
     * Verified claims can never be serialised, whichever way they are reached,
     * so a completion is never kept.
     *
     * @return void
     */
    public function testAVerifiedCompletionCannotBeSerialized(): void
    {
        $completion = $this->assemble(FetchResult::fetched(200, [], self::body(['sub' => self::SUBJECT])));

        $this->expectExceptionObject(new \LogicException('Verified claims cannot be serialised.'));

        serialize($completion);
    }

    /**
     * Rows of `[status, headers, body, reason, logged]`: refused answers that
     * carry what must never be kept.
     *
     * @return iterable<string, array{0: int, 1: array<string, string>, 2: string, 3: \SineMacula\Laravel\Sso\Events\Enums\FailureReason, 4: ?string}>
     */
    public static function provideRefusedAnswers(): iterable
    {
        $error = self::body(['error' => 'invalid_token', 'error_description' => self::DESCRIPTION, 'access_token' => self::ACCESS_TOKEN]);

        yield 'a 401 with a description' => [
            401,
            ['WWW-Authenticate' => 'Bearer error="invalid_token", error_description="' . self::DESCRIPTION . '"'],
            $error,
            FailureReason::PROVIDER_ERROR,
            'invalid_token',
        ];
        yield 'a 403 with a description' => [
            403,
            ['WWW-Authenticate' => 'Bearer error="insufficient_scope", error_description="' . self::DESCRIPTION . '"'],
            $error,
            FailureReason::PROVIDER_ERROR,
            'insufficient_scope',
        ];
        yield 'a 401 with a description for its code' => [
            401,
            ['WWW-Authenticate' => 'Bearer error="' . self::DESCRIPTION . '"'],
            $error,
            FailureReason::PROVIDER_ERROR,
            '[unrecognized]',
        ];
        yield 'a 401 echoing the access token for its code' => [
            401,
            ['WWW-Authenticate' => 'Bearer error="' . self::ACCESS_TOKEN . '"'],
            $error,
            FailureReason::PROVIDER_ERROR,
            '[unrecognized]',
        ];
        yield 'a 500 with a description' => [500, ['WWW-Authenticate' => 'Bearer error_description="' . self::DESCRIPTION . '"'], $error, FailureReason::FETCH_FAILED, null];
        yield 'a malformed body' => [
            200,
            ['Content-Type' => 'application/json'],
            '{"sub":"' . self::SUBJECT . '","error_description":"' . self::DESCRIPTION . '"',
            FailureReason::USERINFO_INVALID,
            null,
        ];
        yield 'a body of another subject' => [
            200,
            ['Content-Type' => 'application/json'],
            self::body(['sub' => 'another', 'email' => self::EMAIL, 'error_description' => self::DESCRIPTION]),
            FailureReason::USERINFO_INVALID,
            null,
        ];
        yield 'a signed answer' => [200, ['Content-Type' => 'application/jwt'], self::ID_TOKEN . self::DESCRIPTION, FailureReason::USERINFO_INVALID, null];
    }

    /**
     * A refused assembly logs an error's code at most, and neither its logs,
     * its completion, what it was given nor its serialised form shows a token,
     * the body, the description or the email.
     *
     * @param  int  $status
     * @param  array<string, string>  $headers
     * @param  string  $body
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?string  $logged
     * @return void
     */
    #[DataProvider('provideRefusedAnswers')]
    public function testARefusedAssemblyKeepsNothing(int $status, array $headers, string $body, FailureReason $reason, ?string $logged): void
    {
        $answer     = FetchResult::fetched($status, $headers, $body);
        $completion = $this->assemble($answer);
        $needles    = [self::ACCESS_TOKEN, self::ID_TOKEN, self::DESCRIPTION, self::EMAIL, $body];

        self::assertSame($reason, $completion->reason);
        self::assertSame($logged === null ? [] : [$logged], array_map(static fn (array $record): mixed => $record['context']['error'] ?? null, $this->capturedLogRecords()));

        $this->assertNothingLoggedContains(...$needles);
        $this->assertNoDumpShows($completion, $needles);
        $this->assertNoDumpShows($answer, [$body]);
        $this->assertNoFetchedRequestShows($needles);

        foreach ($needles as $needle) {
            self::assertStringNotContainsString($needle, serialize($completion));
            self::assertStringNotContainsString($needle, (string) json_encode($completion));
        }
    }

    /**
     * What a completion hands its collaborators shows no token in a dump or in
     * JSON, and cannot be serialised.
     *
     * @return void
     */
    public function testWhatTheAssemblyIsGivenShowsNoToken(): void
    {
        $tokens  = self::tokens();
        $needles = [self::ACCESS_TOKEN, self::ID_TOKEN];

        $this->assertNoDumpShows($tokens, $needles);
        $this->assertNoDumpShows(self::idToken(), [self::ID_TOKEN, self::SUBJECT]);

        foreach ($needles as $needle) {
            self::assertStringNotContainsString($needle, (string) json_encode($tokens));
        }

        $this->expectExceptionObject(new \LogicException('A token response cannot be serialised.'));

        serialize($tokens);
    }

    /**
     * Assert that no dump of the value shows a needle.
     *
     * @param  mixed  $value
     * @param  list<string>  $needles
     * @return void
     */
    private function assertNoDumpShows(mixed $value, array $needles): void
    {
        foreach (self::dumps($value) as $name => $dump) {
            foreach ($needles as $needle) {
                self::assertStringNotContainsString($needle, $dump, $name);
            }
        }
    }

    /**
     * Assert that no dump of a request the fetcher was given shows a needle.
     *
     * @param  list<string>  $needles
     * @return void
     */
    private function assertNoFetchedRequestShows(array $needles): void
    {
        $requests = $this->fetcher->requests();

        self::assertCount(1, $requests);
        $this->assertNoDumpShows($requests[0], $needles);
    }

    /**
     * Assemble the ID token's claims, with UserInfo on and answered as given.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $answer
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function assemble(FetchResult $answer): Completion
    {
        $this->fetcher->respond(self::ENDPOINT, $answer);

        /** @var \Illuminate\Foundation\Application $app */
        $app        = $this->app;
        $connection = new IdentifiedConnection('c1', settings: ['fetch_userinfo' => true, 'userinfo_endpoint' => self::ENDPOINT], linking: true);

        return $app->make(ClaimsAssembler::class)->assemble($connection, OidcOptions::of($connection), self::idToken(), self::tokens(), self::consumed());
    }

    /**
     * The verified result the pipeline builds of the claims.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedClaims  $claims
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function verifiedResult(VerifiedClaims $claims): VerifiedResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ResultBuilder::class)->build($claims, $this->makeConnection(['attribute_mapping' => AttributeMapping::defaults('oidc')]), self::consumed());
    }

    /**
     * The validated ID token, whose protocol claims hold the tokens' values, so
     * a test sees they go no further.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken
     */
    private static function idToken(): ValidatedIdToken
    {
        return new ValidatedIdToken(self::ISSUER, self::SUBJECT, ['iss' => self::ISSUER, 'sub' => self::SUBJECT, 'nonce' => self::ID_TOKEN, 'at_hash' => self::ACCESS_TOKEN]);
    }

    /**
     * The token endpoint's answer.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse
     */
    private static function tokens(): TokenResponse
    {
        return new TokenResponse(self::ID_TOKEN, self::ACCESS_TOKEN);
    }

    /**
     * The request the completion consumed.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     */
    private static function consumed(): ConsumedRequest
    {
        return new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(self::REFERENCE), CarbonImmutable::parse('2026-11-01T09:28:00Z'));
    }

    /**
     * The members as a JSON body.
     *
     * @param  array<string, mixed>  $members
     * @return string
     */
    private static function body(array $members): string
    {
        return (string) json_encode($members, JSON_UNESCAPED_SLASHES);
    }
}
