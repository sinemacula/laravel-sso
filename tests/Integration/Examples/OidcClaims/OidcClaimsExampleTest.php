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
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/oidc-claims.md` (SSO-7.5, SSO-7.7, SSO-2.10,
 * SSO-12.5), on the shared example harness: a connection turns UserInfo on with
 * its endpoint, the asserted email is read from a linked result, and the mapped
 * attributes are read with UserInfo laid over the ID token. Each asserts its
 * outcome and a refusal: UserInfo is not called while it is off, turning it on
 * voids the flow in flight and UserInfo is then called once for each
 * completion, and a connection that turns it on with no endpoint is incomplete
 * and starts nothing; a UserInfo endpoint that does not answer, or answers
 * `401`, refuses the completion; the email and its `email_verified` come from
 * one source, the flag carried only when it is a JSON boolean; and a mapping
 * that reads a protocol value is refused.
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
     * While UserInfo is off a completion never calls it. Turning it on with its
     * endpoint is a trust change, so the flow in flight is refused
     * `connection_unavailable`, and the next completion calls the endpoint
     * once. Removing the endpoint while it is on leaves the connection
     * incomplete, so it starts nothing.
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

        // @snippet-start oidc-fetch-userinfo
        $updated = app(ConnectionService::class)->update($tenantId, $connectionId, ['settings' => [
            'userinfo_endpoint' => 'https://idp.acme.example/userinfo',
            'fetch_userinfo'    => true,
        ]]);
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

        $incomplete = app(ConnectionService::class)->update($tenantId, $connectionId, ['settings' => ['userinfo_endpoint' => null]]);

        self::assertTrue($incomplete->isChanged());
        self::assertFalse($incomplete->connection?->usable);
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $this->startFlow(Purpose::LINK, $connectionId, $this->person)->reason);
    }

    /**
     * While UserInfo is on it must answer: a timeout refuses the completion
     * `fetch_failed` and a `401` refuses it `provider_error`, never going on
     * with the ID token alone, and each request is consumed, so the person
     * starts again once the endpoint answers.
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
     * Rows of `[the ID token's claims, UserInfo's claims or null while it is
     * off, the email, its flag and its source the result asserts]`: each row
     * of the guide's table, and a flag that is not a JSON boolean.
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
     * The asserted email and its `email_verified` are read from one source, the
     * ID token first: UserInfo's flag never vouches for the ID token's email, a
     * flag the source does not state, or states as anything but a JSON boolean,
     * is unknown, and with no email in either source there is none.
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
     * The mapping reads the ID token's claims with UserInfo's laid over them:
     * UserInfo's `name` wins, the ID token's `given_name` stands, and
     * UserInfo's `family_name` is added.
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
     * A mapping that reads a protocol value, here the subject, is refused as
     * `reserved` and changes nothing.
     *
     * @return void
     */
    public function testAMappingCannotReadAProtocolValue(): void
    {
        $connectionId = $this->makeOidcConnection($this->provider);
        $connections  = app(ConnectionService::class);

        $refused = $connections->update(self::TENANT, $connectionId, ['attribute_mapping' => ['display_name' => 'sub']]);

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
     * Link the person through a connection whose provider's ID token carries
     * the claims given and whose UserInfo answers the claims given, or is off
     * when they are `null`, and answer the verified result the link redeemed.
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
     * Start a `link` flow through the connection and complete it at the
     * provider, answering the redirect the browser is sent back with.
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
