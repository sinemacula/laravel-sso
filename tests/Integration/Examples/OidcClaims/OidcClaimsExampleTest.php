<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OidcClaims;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Results\AssertedEmail;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * Integration tests for the examples of `docs/guides/oidc-claims.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type EmailPair array{0: ?string, 1: ?bool, 2: ?\SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource}
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
#[CoversClass(CompletionService::class)]
#[CoversClass(AssertedEmail::class)]
#[CoversClass(VerifiedResult::class)]
final class OidcClaimsExampleTest extends ExampleTestCase
{
    /** @var string The provider's UserInfo endpoint, as the guide names it. */
    private const string USERINFO = 'https://idp.acme.example/userinfo';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The tenant's OpenID provider. */
    private FakeOpenIdProvider $provider;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Make the tenant's OpenID provider and the person.
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
     * Turning UserInfo on voids the flow in flight, then calls it once each.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testUserInfoIsTurnedOnWithItsEndpoint(): void
    {
        $connectionId = $this->makeOidcConnection($this->provider);
        $tenantId     = self::TENANT;

        self::assertTrue($this->complete($connectionId)->hasCode());
        self::assertSame([], $this->userInfoRequests());

        $inFlight = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $client = Clients::browser();
        // @snippet-start oidc-fetch-userinfo
        $updated = app(ConnectionService::class)->update($tenantId, $connectionId, ['settings' => [
            'userinfo_endpoint' => 'https://idp.acme.example/userinfo',
            'fetch_userinfo'    => true,
        ]], $client);
        // @snippet-end oidc-fetch-userinfo
        $changed = $updated->changedSettings;

        sort($changed);

        self::assertTrue($updated->isChanged());
        self::assertSame(['fetch_userinfo', 'userinfo_endpoint'], $changed);
        self::assertTrue($updated->connection?->usable);

        $voided = $this->respondAtProvider($this->provider, $connectionId, $inFlight);

        self::assertFalse($voided->hasCode());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE->value, $voided->error);
        self::assertTrue($this->complete($connectionId)->hasCode());
        self::assertSame([self::USERINFO], $this->userInfoRequests());

        $incomplete = app(ConnectionService::class)->update($tenantId, $connectionId, ['settings' => ['userinfo_endpoint' => null]], Clients::browser());

        self::assertTrue($incomplete->isChanged());
        self::assertFalse($incomplete->connection?->usable);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->startFlow(Purpose::LINK, $connectionId, $this->person)->reason);
    }

    /**
     * A UserInfo timeout or `401` refuses the completion.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testUserInfoFailsClosed(): void
    {
        $connectionId = $this->makeOidcConnection($this->provider, ['userinfo_endpoint' => self::USERINFO, 'fetch_userinfo' => true]);

        $this->provider->respond('userinfo', FetchResult::failed());

        $timedOut = $this->complete($connectionId);

        $this->provider->respond('userinfo', FakeTokenEndpoint::json(401, ['error' => 'invalid_token']));

        $unauthorized = $this->complete($connectionId);

        $this->provider->respond('userinfo', null);

        self::assertFalse($timedOut->hasCode());
        self::assertSame(FailureReason::FETCH_FAILED->value, $timedOut->error);
        self::assertFalse($unauthorized->hasCode());
        self::assertSame(FailureReason::PROVIDER_ERROR->value, $unauthorized->error);
        self::assertTrue($this->complete($connectionId)->hasCode());
        self::assertSame([self::USERINFO, self::USERINFO, self::USERINFO], $this->userInfoRequests());
    }

    /**
     * The ID token's claims, UserInfo's (`null` when off) and the email pair.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: ?array<string, mixed>, 2: EmailPair}>
     */
    public static function provideEmailPairs(): iterable
    {
        $a = 'a@acme.example';
        $b = 'b@acme.example';

        yield 'a verified ID token email' => [['email' => $a, 'email_verified' => true], ['email' => $b, 'email_verified' => true], [$a, true, LinkingEmailSource::ID_TOKEN]];
        yield 'an unverified ID token email' => [['email' => $a, 'email_verified' => false], ['email' => $b, 'email_verified' => true], [$a, false, LinkingEmailSource::ID_TOKEN]];
        yield 'an ID token email with no flag' => [['email' => $a], ['email' => $a, 'email_verified' => true], [$a, null, LinkingEmailSource::ID_TOKEN]];
        yield 'a flag with no ID token email' => [['email_verified' => true], ['email' => $b], [$b, null, LinkingEmailSource::USERINFO]];
        yield 'a verified UserInfo email' => [[], ['email' => $b, 'email_verified' => true], [$b, true, LinkingEmailSource::USERINFO]];
        yield 'no email at all' => [[], ['name' => 'A Person'], [null, null, null]];
        yield 'no email with UserInfo off' => [[], null, [null, null, null]];
        yield 'a flag that is a string' => [['email' => $a, 'email_verified' => 'true'], [], [$a, null, LinkingEmailSource::ID_TOKEN]];
    }

    /**
     * The email and its flag come from one source, the ID token first.
     *
     * @param  array<string, mixed>  $idToken
     * @param  ?array<string, mixed>  $userInfo
     * @param  EmailPair  $expected
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideEmailPairs')]
    public function testTheEmailAndItsFlagComeFromOneSource(array $idToken, ?array $userInfo, array $expected): void
    {
        $result = $this->linkWith($idToken, $userInfo);

        self::assertSame($expected, self::readAssertedEmail($result));
        self::assertSame($expected[0] === null, $result->assertedEmail === null);
    }

    /**
     * UserInfo's claims are laid over the ID token's for the mapping.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testUserInfoWinsForAClaimBothState(): void
    {
        $result = $this->linkWith(['name' => 'A Person', 'given_name' => 'A'], ['name' => 'Ada Person', 'family_name' => 'Person']);

        // @snippet-start oidc-mapped-attributes
        $givenName   = $result->attributes['given_name'];   // "A": the ID token's alone
        $familyName  = $result->attributes['family_name'];  // "Person": UserInfo's alone
        $displayName = $result->attributes['display_name']; // "Ada Person": UserInfo's name wins
        // @snippet-end oidc-mapped-attributes
        $attributes = $result->attributes;

        ksort($attributes);

        self::assertSame(['A', 'Person', 'Ada Person'], [$givenName, $familyName, $displayName]);
        self::assertSame(['display_name' => 'Ada Person', 'family_name' => 'Person', 'given_name' => 'A'], $attributes);
        self::assertNull($result->assertedEmail);
    }

    /**
     * A mapping that reads a protocol value is refused as `reserved`.
     *
     * @return void
     */
    public function testAMappingCannotReadAProtocolValue(): void
    {
        $connectionId = $this->makeOidcConnection($this->provider);
        $connections  = app(ConnectionService::class);

        $refused = $connections->update(self::TENANT, $connectionId, ['attribute_mapping' => ['display_name' => 'sub']], Clients::browser());

        self::assertTrue($refused->isInvalid());
        self::assertSame(
            [['attribute_mapping.display_name', 'reserved']],
            array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $refused->violations),
        );
        self::assertSame('name', $connections->get(self::TENANT, $connectionId)?->attributeMapping['display_name'] ?? null);
    }

    /**
     * Read the asserted email of the verified result, as an application does.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return EmailPair
     */
    private static function readAssertedEmail(VerifiedResult $result): array
    {
        // @snippet-start oidc-asserted-email
        $asserted = $result->assertedEmail;

        $email    = $asserted?->email();  // The email, exactly as asserted
        $verified = $asserted?->verified; // Verified, not verified, or unknown when null
        $source   = $asserted?->source;   // Where both came from: the ID token or UserInfo
        // @snippet-end oidc-asserted-email
        return [$email, $verified, $source];
    }

    /**
     * Link the person with these claims and answer the verified result.
     *
     * @param  array<string, mixed>  $idToken
     * @param  ?array<string, mixed>  $userInfo
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \Random\RandomException
     */
    private function linkWith(array $idToken, ?array $userInfo): VerifiedResult
    {
        $settings     = $userInfo === null ? [] : ['userinfo_endpoint' => self::USERINFO, 'fetch_userinfo' => true];
        $connectionId = $this->makeOidcConnection($this->provider->withUserInfo($userInfo ?? []), $settings);
        $start        = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $redirect = $this->respondAtProvider($this->provider, $connectionId, $start, static function (FakeIdToken $token) use ($idToken): FakeIdToken {

            foreach ($idToken as $claim => $value) {
                $token = $token->with($claim, $value);
            }

            return $token;
        });

        $linked = $this->redeemLink($connectionId, $redirect, $start, $this->person);

        self::assertTrue($linked->isRedeemed());

        return $linked->result ?? self::fail('The link carried no verified result.');
    }

    /**
     * Start a `link` flow and complete it at the provider.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Testing\HandoffRedirect
     *
     * @throws \Random\RandomException
     */
    private function complete(string $connectionId): HandoffRedirect
    {
        return $this->respondAtProvider($this->provider, $connectionId, $this->startFlow(Purpose::LINK, $connectionId, $this->person));
    }

    /**
     * The URL of every UserInfo request made so far, in order.
     *
     * @return list<string>
     */
    private function userInfoRequests(): array
    {
        $requests = array_filter($this->fetcher->requests(), static fn (FetchRequest $request): bool => $request->purpose === FetchPurpose::USERINFO);

        return array_values(array_map(static fn (FetchRequest $request): string => $request->url, $requests));
    }
}
