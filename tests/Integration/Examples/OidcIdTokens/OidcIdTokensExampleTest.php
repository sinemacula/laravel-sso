<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OidcIdTokens;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * Integration tests for the examples of `docs/guides/oidc-id-tokens.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
#[CoversClass(CompletionService::class)]
final class OidcIdTokensExampleTest extends ExampleTestCase
{
    /** @var string The audience the provider adds for the tenant's API, as the guide names it. */
    private const string API = 'https://api.acme.example';

    /** @var int The clock skew, `sso.clock.skew_seconds` by default. */
    private const int SKEW = 60;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Make the provider, reading the package's clock, and the person.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = new FakeOpenIdProvider('https://idp.acme.example', clock: $this->clock);
        $this->person   = new IdentityReference('App\Models\User', 'person-1');
    }

    /**
     * Allowing `ES256` voids the flow in flight, then both algorithms complete.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAllowsAnotherAlgorithm(): void
    {
        $rsa = $this->provider->signingKey();
        $ec  = FakeSigningKey::ec('ec-1', 'P-256');

        $this->provider->publish($ec)->signWith($ec, 'ES256');

        $connectionId = $this->makeOidcConnection($this->provider);
        $tenantId     = self::TENANT;
        $offTheList   = $this->complete($connectionId);

        self::assertSame(FailureReason::SIGNATURE_INVALID->value, $offTheList->error);
        self::assertSame(0, $this->jwksFetches());

        $inFlight = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $client = Clients::browser();
        // @snippet-start oidc-id-token-algorithms
        $updated = app(ConnectionService::class)->update($tenantId, $connectionId, ['settings' => [
            'id_token_algorithms' => ['RS256', 'ES256'],
        ]], $client);
        // @snippet-end oidc-id-token-algorithms
        self::assertSame(['id_token_algorithms'], $updated->changedSettings);
        self::assertSame(['RS256', 'ES256'], $updated->connection?->settings['id_token_algorithms']);

        $voided = $this->respondAtProvider($this->provider, $connectionId, $inFlight);

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE->value, $voided->error);
        self::assertTrue($this->complete($connectionId)->hasCode());

        $this->provider->signWith($rsa, 'RS256');

        self::assertTrue($this->complete($connectionId)->hasCode());
        self::assertSame(1, $this->jwksFetches());
    }

    /**
     * `none` and every `HS*` algorithm are refused as `not_allowed`.
     *
     * @return void
     */
    public function testNeverAllowsNoneOrAnHmac(): void
    {
        $connectionId = $this->makeOidcConnection($this->provider);

        $refused = app(ConnectionService::class)->update(self::TENANT, $connectionId, ['settings' => [
            'id_token_algorithms' => ['RS256', 'none', 'HS256'],
        ]], Clients::browser());

        $notAllowed = ViolationCode::NOT_ALLOWED->value;

        self::assertTrue($refused->isInvalid());
        self::assertSame([['id_token_algorithms.1', $notAllowed], ['id_token_algorithms.2', $notAllowed]], self::violationsOf($refused));
        self::assertSame(['RS256'], app(ConnectionService::class)->get(self::TENANT, $connectionId)?->settings['id_token_algorithms']);
    }

    /**
     * A trusted audience completes only with the client and a matching `azp`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTrustsAnotherAudience(): void
    {
        $connectionId = $this->makeOidcConnection($this->provider);
        $tenantId     = self::TENANT;
        $clientId     = FakeOpenIdProvider::CLIENT_ID;
        $withApi      = static fn (FakeIdToken $token): FakeIdToken => $token->with('aud', [$clientId, self::API])->with('azp', $clientId);

        // A token that would be refused fetches no keys, so a plain sign-in
        // stores them first
        self::assertTrue($this->complete($connectionId)->hasCode());
        self::assertSame(FailureReason::AUDIENCE_MISMATCH->value, $this->complete($connectionId, $withApi)->error);

        $client = Clients::browser();
        // @snippet-start oidc-trusted-audiences
        $updated = app(ConnectionService::class)->update($tenantId, $connectionId, ['settings' => [
            'trusted_audiences' => ['https://api.acme.example'],
        ]], $client);
        // @snippet-end oidc-trusted-audiences
        self::assertSame(['trusted_audiences'], $updated->changedSettings);
        self::assertTrue($this->complete($connectionId, $withApi)->hasCode());

        $refusals = [
            'no azp'        => static fn (FakeIdToken $token): FakeIdToken => $withApi($token)->without('azp'),
            'another azp'   => static fn (FakeIdToken $token): FakeIdToken => $withApi($token)->with('azp', 'another-client'),
            'another case'  => static fn (FakeIdToken $token): FakeIdToken => $withApi($token)->with('aud', [$clientId, strtoupper(self::API)]),
            'the API alone' => static fn (FakeIdToken $token): FakeIdToken => $token->with('aud', self::API),
        ];

        foreach ($refusals as $case => $tailor) {
            self::assertSame(FailureReason::AUDIENCE_MISMATCH->value, $this->complete($connectionId, $tailor)->error, $case);
        }
    }

    /**
     * Once `max_age` is set it is sent, and `auth_time` is held to it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAsksForARecentAuthentication(): void
    {
        $connectionId = $this->makeOidcConnection($this->provider);
        $tenantId     = self::TENANT;
        $noAuthTime   = static fn (FakeIdToken $token): FakeIdToken => $token->without('auth_time');

        self::assertSame([null, true], $this->completeAsked($connectionId, $noAuthTime));

        $client = Clients::browser();
        // @snippet-start oidc-max-age
        $updated = app(ConnectionService::class)->update($tenantId, $connectionId, ['settings' => [
            'max_age' => 3600,
        ]], $client);
        // @snippet-end oidc-max-age
        self::assertSame(['max_age'], $updated->changedSettings);

        $anHourAgo  = static fn (FakeIdToken $token): FakeIdToken => $token->with('auth_time', self::issuedAt($token) - 3600);
        $tooLongAgo = static fn (FakeIdToken $token): FakeIdToken => $token->with('auth_time', self::issuedAt($token) - 3600 - self::SKEW - 1);

        self::assertSame(['3600', true], $this->completeAsked($connectionId, $anHourAgo));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED->value, $this->complete($connectionId, $tooLongAgo)->error);
        self::assertSame(FailureReason::ID_TOKEN_INVALID->value, $this->complete($connectionId, $noAuthTime)->error);
    }

    /**
     * A `max_age` over a week, or not an integer, is refused.
     *
     * @return void
     */
    public function testRefusesAMaxAgeOverAWeek(): void
    {
        $connectionId = $this->makeOidcConnection($this->provider);
        $connections  = app(ConnectionService::class);

        $overAWeek = $connections->update(self::TENANT, $connectionId, ['settings' => ['max_age' => 604801]], Clients::browser());
        $aString   = $connections->update(self::TENANT, $connectionId, ['settings' => ['max_age' => '3600']], Clients::browser());

        self::assertSame([['max_age', ViolationCode::NOT_ALLOWED->value]], self::violationsOf($overAWeek));
        self::assertSame([['max_age', ViolationCode::INVALID_TYPE->value]], self::violationsOf($aString));
        $connection = $connections->get(self::TENANT, $connectionId);

        self::assertNotNull($connection);
        self::assertArrayNotHasKey('max_age', $connection->settings);
    }

    /**
     * Start a `link` flow and complete it, tailoring the ID token if asked.
     *
     * @param  string  $connectionId
     * @param  ?\Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     *
     * @throws \Random\RandomException
     */
    private function complete(string $connectionId, ?\Closure $tailor = null): HandoffRedirect
    {
        return $this->respondAtProvider($this->provider, $connectionId, $this->startFlow(Purpose::LINK, $connectionId, $this->person), $tailor);
    }

    /**
     * Complete a tailored `link` flow: the `max_age` sent and whether it coded.
     *
     * @param  string  $connectionId
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken): \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $tailor
     * @return array{0: ?string, 1: bool}
     *
     * @throws \Random\RandomException
     */
    private function completeAsked(string $connectionId, \Closure $tailor): array
    {
        $grant    = $this->provider->authorize($this->startFlow(Purpose::LINK, $connectionId, $this->person), $tailor);
        $result   = app(CompletionService::class)->complete(CompletionEndpoint::CALLBACK, $connectionId, new CompletionRequest('GET', $grant->query(), []), Clients::browser());
        $redirect = HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'GET'));

        return [$grant->parameter('max_age'), $redirect->hasCode()];
    }

    /**
     * How many times the provider's JWKS has been fetched.
     *
     * @return int
     */
    private function jwksFetches(): int
    {
        $jwks = $this->provider->endpoint('jwks');

        return count(array_filter($this->fetcher->requests(), static fn (FetchRequest $request): bool => $request->url === $jwks));
    }

    /**
     * Each violation of the result, as its setting and its code.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(ConnectionResult $result): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $result->violations);
    }

    /**
     * When the token was issued.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken  $token
     * @return int
     */
    private static function issuedAt(FakeIdToken $token): int
    {
        $issued = $token->claims()['iat'] ?? null;

        return is_int($issued) ? $issued : 0;
    }
}
