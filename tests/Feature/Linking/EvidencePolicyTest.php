<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\EvidenceRules;
use SineMacula\Laravel\Sso\Evidence\InsufficientEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClaimsAssembler;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\TokenResponse;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\ValidatedIdToken;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AuthenticationRules;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\Fixtures\Results\ExampleResults;
use Tests\TestCase;

/**
 * Feature tests of the evidence contract asked directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionEvidencePolicy::class)]
#[CoversClass(InsufficientEvidence::class)]
#[CoversClass(EvidenceRules::class)]
#[CoversClass(ClaimsAssembler::class)]
#[CoversClass(AuthenticationRules::class)]
final class EvidencePolicyTest extends TestCase
{
    /** @var string The connection's id. */
    private const string CONNECTION_ID = '01jbexampleconnection00000';

    /** @var string The issuer of a token. */
    private const string ISSUER = 'https://op.example.test';

    /** @var string The subject of a token. */
    private const string SUBJECT = 'the-subject';

    /** @var string The connection's UserInfo endpoint. */
    private const string ENDPOINT = 'https://op.example.test/userinfo';

    /** @var string A class a token states. */
    private const string TOKEN_CLASS = 'urn:example:token-class';

    /** @var string A class UserInfo states. */
    private const string USERINFO_CLASS = 'urn:example:userinfo-class';

    /** @var string When the provider authenticated: 2026-11-01T09:29:00Z. */
    private const string AUTHENTICATED_AT = '2026-11-01T09:29:00Z';

    /** @var int The same instant, as a token states it. */
    private const int AUTHENTICATED_AT_SECONDS = 1793525340;

    /** @var array<string, mixed> A policy that accepts a password. */
    private const array PASSWORD = ['amr' => ['pwd'], 'combinations' => [['amr' => ['pwd']]]];

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher UserInfo is requested through. */
    private FakeFetcher $fetcher;

    /**
     * Set the bounds apart from their defaults, and bind the fake fetcher.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.linking.evidence_max_age_seconds', 600);
        config()->set('sso.clock.skew_seconds', 30);
    }

    /**
     * The contract's default accepts nothing, whatever the connection holds and
     * the result states.
     *
     * @return void
     */
    public function testTheDefaultAcceptsNothing(): void
    {
        $policy = app(EvidencePolicy::class);

        self::assertInstanceOf(InsufficientEvidence::class, $policy);
        self::assertNull($policy->evaluate(self::resultWith(new AuthenticationContext(self::at(), ['pwd'])), self::connection(self::PASSWORD), self::at()));
    }

    /**
     * What is accepted is the connection as the credential reference, the
     * provider's time exactly, the accepted methods and the raw class.
     *
     * @return void
     */
    public function testWhatIsAccepted(): void
    {
        $at       = self::at()->subMinute();
        $class    = 'urn:example:not-listed';
        $evidence = self::policy()->evaluate(self::resultWith(new AuthenticationContext($at, ['otp', 'pwd'], $class, 'session-1')), self::connection(self::PASSWORD), self::at());

        self::assertInstanceOf(AcceptedEvidence::class, $evidence);
        self::assertSame(self::CONNECTION_ID, $evidence->connectionId);
        self::assertSame($at, $evidence->authenticatedAt);
        self::assertSame(['pwd'], $evidence->methods());
        self::assertSame($class, $evidence->rawContext());
    }

    /**
     * No raw class stated is none carried.
     *
     * @return void
     */
    public function testNoRawClassIsNoneCarried(): void
    {
        $evidence = self::policy()->evaluate(self::resultWith(new AuthenticationContext(self::at(), ['pwd'])), self::connection(self::PASSWORD), self::at());

        self::assertNull($evidence?->rawContext());
        self::assertSame(['pwd'], $evidence?->methods());
    }

    /**
     * Rows of `[microseconds from the instant asked, whether it is accepted]`,
     * under a maximum age of 600 seconds and a skew of 30.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideTimes(): iterable
    {
        yield 'now' => [0, true];
        yield 'one second under the maximum age' => [-599000000, true];
        yield 'at the maximum age' => [-600000000, true];
        yield 'a microsecond over the maximum age' => [-600000001, false];
        yield 'one second over the maximum age' => [-601000000, false];
        yield 'one second under the skew' => [29000000, true];
        yield 'at the skew' => [30000000, true];
        yield 'a microsecond past the skew' => [30000001, false];
        yield 'one second past the skew' => [31000000, false];
    }

    /**
     * Each bound of the authentication time, against the instant asked.
     *
     * @param  int  $microseconds
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideTimes')]
    public function testTheAuthenticationTimeIsBounded(int $microseconds, bool $accepted): void
    {
        $context = new AuthenticationContext(self::at()->addMicroseconds($microseconds), ['pwd']);

        self::assertSame($accepted, self::policy()->evaluate(self::resultWith($context), self::connection(self::PASSWORD), self::at()) !== null);
    }

    /**
     * The bounds are read on each call, and neither is a default in disguise.
     *
     * @return void
     */
    public function testTheBoundsAreReadOnEachCall(): void
    {
        $policy = self::policy();
        $old    = self::resultWith(new AuthenticationContext(self::at()->subSeconds(700), ['pwd']));
        $ahead  = self::resultWith(new AuthenticationContext(self::at()->addSeconds(40), ['pwd']));

        self::assertNull($policy->evaluate($old, self::connection(self::PASSWORD), self::at()));
        self::assertNull($policy->evaluate($ahead, self::connection(self::PASSWORD), self::at()));

        config()->set('sso.linking.evidence_max_age_seconds', 700);
        config()->set('sso.clock.skew_seconds', 40);

        self::assertNotNull($policy->evaluate($old, self::connection(self::PASSWORD), self::at()));
        self::assertNotNull($policy->evaluate($ahead, self::connection(self::PASSWORD), self::at()));
    }

    /**
     * Rows of `[connection maximum age, ceiling, authentication age,
     * accepted]`: a stored value above the ceiling is clamped to it.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int, 3: bool}>
     */
    public static function provideOwnMaximumAges(): iterable
    {
        yield 'under its own bound' => [120, 600, 119, true];
        yield 'at its own bound' => [120, 600, 120, true];
        yield 'over its own bound, under the ceiling' => [120, 600, 121, false];
        yield 'equal to the ceiling, at it' => [600, 600, 600, true];
        yield 'equal to the ceiling, over it' => [600, 600, 601, false];
        yield 'one second' => [1, 600, 1, true];
        yield 'one second, over it' => [1, 600, 2, false];
        yield 'above a lowered ceiling, at the ceiling' => [600, 300, 300, true];
        yield 'above a lowered ceiling, over the ceiling' => [600, 300, 301, false];
    }

    /**
     * A connection's own maximum age tightens the ceiling, and the ceiling as
     * it is now always wins.
     *
     * @param  int  $own
     * @param  int  $ceiling
     * @param  int  $age
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideOwnMaximumAges')]
    public function testAConnectionsOwnMaximumAgeOnlyTightens(int $own, int $ceiling, int $age, bool $accepted): void
    {
        config()->set('sso.linking.evidence_max_age_seconds', $ceiling);

        $context = new AuthenticationContext(self::at()->subSeconds($age), ['pwd']);

        self::assertSame($accepted, self::policy()->evaluate(self::resultWith($context), self::connection(self::PASSWORD + ['max_age_seconds' => $own]), self::at()) !== null);
    }

    /**
     * Rows of `[what a stored maximum age holds]`: a policy holding anything
     * but a whole number of at least one is malformed, so insufficient.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedMaximumAges(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
        yield 'a string' => ['120'];
        yield 'a fraction' => [120.5];
        yield 'nothing' => [null];
        yield 'true' => [true];
    }

    /**
     * A stored maximum age that is no whole number of at least one accepts
     * nothing at all.
     *
     * @param  mixed  $stored
     * @return void
     */
    #[DataProvider('provideMalformedMaximumAges')]
    public function testAMalformedMaximumAgeIsInsufficient(mixed $stored): void
    {
        $context = new AuthenticationContext(self::at(), ['pwd']);

        self::assertNull(self::policy()->evaluate(self::resultWith($context), self::connection(self::PASSWORD + ['max_age_seconds' => $stored]), self::at()));
    }

    /**
     * A provider-specific `amr` beside an accepted standard one is left out,
     * and alone satisfies nothing.
     *
     * @return void
     */
    public function testAProviderSpecificMethodDoesNotForceClassOnlyEvidence(): void
    {
        $stated   = new AuthenticationContext(self::at(), ['provider-specific', 'pwd'], 'urn:example:unlisted');
        $evidence = self::policy()->evaluate(self::resultWith($stated), self::connection(self::PASSWORD), self::at());

        self::assertNotNull($evidence);
        self::assertSame(['pwd'], $evidence->methods());
        self::assertSame('urn:example:unlisted', $evidence->rawContext());

        $alone = new AuthenticationContext(self::at(), ['provider-specific'], 'urn:example:unlisted');

        self::assertNull(self::policy()->evaluate(self::resultWith($alone), self::connection(self::PASSWORD), self::at()));
    }

    /**
     * A registered driver's methods and class are read as normalised evidence,
     * whatever its wire protocol.
     *
     * @return void
     */
    public function testARegisteredDriversMethodsAreItsNormalisedEvidence(): void
    {
        $context  = new AuthenticationContext(self::at(), ['pwd']);
        $evidence = self::policy()->evaluate(self::resultWith($context, protocol: 'a-registered-driver'), self::connection(self::PASSWORD, 'a-registered-driver'), self::at());

        self::assertSame(['pwd'], $evidence?->methods());
    }

    /**
     * No authentication time is insufficient, whatever else it states.
     *
     * @return void
     */
    public function testNoAuthenticationTimeIsInsufficient(): void
    {
        self::assertNull(self::policy()->evaluate(self::resultWith(new AuthenticationContext(null, ['pwd'])), self::connection(self::PASSWORD), self::at()));
    }

    /**
     * Rows of `[connection id, tenant, protocol]`: a result of anything but
     * exactly the connection's own.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideOtherOwners(): iterable
    {
        yield 'another connection' => ['01jbotherconnection0000000', 'tenant-1', 'oidc'];
        yield 'another tenant' => [self::CONNECTION_ID, 'tenant-2', 'oidc'];
        yield 'a tenant differing by case' => [self::CONNECTION_ID, 'TENANT-1', 'oidc'];
        yield 'another protocol' => [self::CONNECTION_ID, 'tenant-1', 'saml2'];
    }

    /**
     * A result of another connection, tenant or protocol is insufficient.
     *
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @return void
     */
    #[DataProvider('provideOtherOwners')]
    public function testAResultOfAnotherOwnerIsInsufficient(string $connectionId, string $tenantId, string $protocol): void
    {
        $result = self::resultWith(new AuthenticationContext(self::at(), ['pwd']), Purpose::SIGN_IN, $connectionId, $tenantId, $protocol);

        self::assertNull(self::policy()->evaluate($result, self::connection(self::PASSWORD), self::at()));
    }

    /**
     * Rows of `[purpose, whether it may give evidence]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: bool}>
     */
    public static function providePurposes(): iterable
    {
        yield 'sign_in' => [Purpose::SIGN_IN, true];
        yield 'reauthenticate' => [Purpose::REAUTHENTICATE, true];
        yield 'link' => [Purpose::LINK, false];
    }

    /**
     * A `link` result proves nothing, even were it asked.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('providePurposes')]
    public function testOnlyALinkProvesNothing(Purpose $purpose, bool $accepted): void
    {
        $result = self::resultWith(new AuthenticationContext(self::at(), ['pwd']), $purpose);

        self::assertSame($accepted, self::policy()->evaluate($result, self::connection(self::PASSWORD), self::at()) !== null);
    }

    /**
     * Rows of `[what the column holds]`: none is a policy, and none throws.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideStoredColumns(): iterable
    {
        yield 'SQL null' => [null];
        yield 'JSON null' => ['null'];
        yield 'an empty list' => ['[]'];
        yield 'an empty map' => ['{}'];
        yield 'a number' => ['5'];
        yield 'a string' => ['"amr"'];
        yield 'true' => ['true'];
        yield 'what is not JSON' => ['not json'];
        yield 'the accepted list a string' => ['{"amr":"pwd","combinations":[{"amr":["pwd"]}]}'];
        yield 'no combinations' => ['{"amr":["pwd"]}'];
        yield 'a combination naming nothing' => ['{"amr":["pwd"],"combinations":[{}]}'];
        yield 'a combination not accepted' => ['{"amr":["pwd"],"combinations":[{"amr":["otp"]}]}'];
        yield 'an unregistered method' => ['{"amr":["custom"],"combinations":[{"amr":["custom"]}]}'];
        yield 'an unknown name' => ['{"amr":["pwd"],"combinations":[{"amr":["pwd"]}],"other":true}'];
    }

    /**
     * A policy empty or malformed is insufficient, never an exception.
     *
     * @param  ?string  $column
     * @return void
     */
    #[DataProvider('provideStoredColumns')]
    public function testAPolicyThatIsNoPolicyIsInsufficient(?string $column): void
    {
        $connection = new Connection;

        $connection->setRawAttributes(['id' => self::CONNECTION_ID, 'tenant_id' => 'tenant-1', 'protocol' => 'oidc', 'evidence_policy' => $column]);

        self::assertNull(self::policy()->evaluate(self::resultWith(new AuthenticationContext(self::at(), ['pwd'])), $connection, self::at()));
    }

    /**
     * A connection holding no policy accepts nothing, as any contract's answers
     * it.
     *
     * @return void
     */
    public function testAConnectionWithNoPolicyAcceptsNothing(): void
    {
        self::assertNull(self::policy()->evaluate(self::resultWith(new AuthenticationContext(self::at(), ['pwd'])), new IdentifiedConnection(self::CONNECTION_ID), self::at()));
    }

    /**
     * A policy read for its connection's protocol: another's names are
     * malformed there.
     *
     * @return void
     */
    public function testAPolicyIsReadForItsConnectionsProtocol(): void
    {
        $result = self::resultWith(new AuthenticationContext(self::at(), ['pwd']), protocol: 'saml2');

        self::assertNull(self::policy()->evaluate($result, self::connection(self::PASSWORD, 'saml2'), self::at()));
    }

    /**
     * Anything else a connection throws is an error, and propagates.
     *
     * @return void
     */
    public function testAnErrorPropagates(): void
    {
        $connection = self::createStub(SsoConnection::class);

        $connection->method('getConnectionId')->willReturn(self::CONNECTION_ID);
        $connection->method('getTenantId')->willReturn('tenant-1');
        $connection->method('getProtocol')->willReturn('oidc');
        $connection->method('getEvidencePolicy')->willThrowException(new \RuntimeException('The store failed.'));

        $this->expectExceptionObject(new \RuntimeException('The store failed.'));

        self::policy()->evaluate(self::resultWith(new AuthenticationContext(self::at(), ['pwd'])), $connection, self::at());
    }

    /**
     * Rows of `[configuration key, value, its message]`: a bound configured out
     * of range is an error, never a wider window.
     *
     * @return iterable<string, array{0: string, 1: int, 2: string}>
     */
    public static function provideBadBounds(): iterable
    {
        yield 'the maximum age' => ['sso.linking.evidence_max_age_seconds', 59, 'sso.linking.evidence_max_age_seconds must be an integer from 60 to 3600.'];
        yield 'the skew' => ['sso.clock.skew_seconds', 301, 'sso.clock.skew_seconds must be an integer from 0 to 300.'];
    }

    /**
     * A bound configured out of range fails closed.
     *
     * @param  string  $key
     * @param  int  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideBadBounds')]
    public function testABoundOutOfRangeFailsClosed(string $key, int $value, string $message): void
    {
        config()->set($key, $value);

        $this->expectExceptionObject(new \InvalidArgumentException($message));

        self::policy()->evaluate(self::resultWith(new AuthenticationContext(self::at(), ['pwd'])), self::connection(self::PASSWORD), self::at());
    }

    /**
     * UserInfo never adds to the evidence: only the ID token's statement is
     * judged.
     *
     * @return void
     */
    public function testUserInfoNeverStrengthensTheEvidence(): void
    {
        $userInfo = ['sub' => self::SUBJECT, 'amr' => ['otp'], 'acr' => self::USERINFO_CLASS, 'auth_time' => self::AUTHENTICATED_AT_SECONDS + 30];
        $policy   = ['amr' => ['pwd', 'otp'], 'acr' => [self::TOKEN_CLASS, self::USERINFO_CLASS], 'combinations' => [['amr' => ['pwd'], 'acr' => self::TOKEN_CLASS]]];
        $token    = ['amr' => ['pwd'], 'acr' => self::TOKEN_CLASS, 'auth_time' => self::AUTHENTICATED_AT_SECONDS];

        $evidence = self::policy()->evaluate($this->resultOf($this->assembled($token, $userInfo)), self::connection($policy), self::at());

        self::assertSame(['pwd'], $evidence?->methods());
        self::assertSame(self::TOKEN_CLASS, $evidence->rawContext());
        self::assertSame(self::AUTHENTICATED_AT, $evidence->authenticatedAt->utc()->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * Rows of `[what the ID token states, the combination]`: what UserInfo
     * would complete, if it could.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
     */
    public static function provideWhatUserInfoCannotComplete(): iterable
    {
        $at = ['auth_time' => self::AUTHENTICATED_AT_SECONDS];

        yield 'a second method' => [['amr' => ['pwd']] + $at, ['amr' => ['pwd', 'otp']]];
        yield 'the only method' => [$at, ['amr' => ['otp']]];
        yield 'the class' => [['amr' => ['pwd']] + $at, ['amr' => ['pwd'], 'acr' => self::USERINFO_CLASS]];
        yield 'the time' => [['amr' => ['otp']], ['amr' => ['otp']]];
    }

    /**
     * What UserInfo states never completes a combination.
     *
     * @param  array<string, mixed>  $token
     * @param  array<string, mixed>  $combination
     * @return void
     */
    #[DataProvider('provideWhatUserInfoCannotComplete')]
    public function testUserInfoCompletesNoCombination(array $token, array $combination): void
    {
        $userInfo = ['sub' => self::SUBJECT, 'amr' => ['otp'], 'acr' => self::USERINFO_CLASS, 'auth_time' => self::AUTHENTICATED_AT_SECONDS];
        $policy   = ['amr' => ['pwd', 'otp'], 'acr' => [self::USERINFO_CLASS], 'combinations' => [$combination]];

        self::assertNull(self::policy()->evaluate($this->resultOf($this->assembled($token, $userInfo)), self::connection($policy), self::at()));
    }

    /**
     * Rows of `[claims]`: a method that is not a string never reaches a result,
     * since the driver refuses the token that stated it.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideNonStringMethods(): iterable
    {
        yield 'a string' => [['amr' => 'pwd']];
        yield 'a map' => [['amr' => ['a' => 'pwd']]];
        yield 'null' => [['amr' => null]];
        yield 'holding a number' => [['amr' => ['pwd', 1]]];
        yield 'holding a boolean' => [['amr' => ['pwd', true]]];
        yield 'holding a list' => [['amr' => ['pwd', ['otp']]]];
        yield 'holding an empty string' => [['amr' => ['pwd', '']]];
    }

    /**
     * A driver stops a method that is not a string at the token, so what the
     * evidence contract reads is only ever a list of strings.
     *
     * @param  array<string, mixed>  $claims
     * @return void
     */
    #[DataProvider('provideNonStringMethods')]
    public function testAMethodThatIsNoStringNeverReachesAResult(array $claims): void
    {
        $completion = $this->assembled($claims);

        self::assertSame(FailureReason::ID_TOKEN_INVALID, $completion->reason);
        self::assertNull($completion->claims);
    }

    /**
     * A result's context itself refuses a method that is not a string.
     *
     * @return void
     */
    public function testAContextRefusesAMethodThatIsNoString(): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('Each authentication method is a string.'));

        new AuthenticationContext(self::at(), ['pwd', 1]); // @phpstan-ignore argument.type
    }

    /**
     * A SAML assertion states one class and no methods: its one validated
     * statement is the whole of what is judged.
     *
     * @return void
     */
    public function testASamlContextIsItsOneStatement(): void
    {
        $class   = 'urn:example:saml-class';
        $context = AuthenticationRules::context(self::assertion([self::statement($class)]), self::validation());

        self::assertInstanceOf(AuthenticationContext::class, $context);
        self::assertSame([], $context->methods);

        $policy   = ['authn_context_class_ref' => [$class], 'combinations' => [['authn_context_class_ref' => $class]]];
        $evidence = self::policy()->evaluate(self::resultWith($context, protocol: 'saml2'), self::connection($policy, 'saml2'), self::at());

        self::assertSame([], $evidence?->methods());
        self::assertSame($class, $evidence->rawContext());
        self::assertSame(self::AUTHENTICATED_AT, $evidence->authenticatedAt->utc()->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * A second statement is never read for its class: the assertion is refused.
     *
     * @return void
     */
    public function testASecondStatementIsNeverRead(): void
    {
        $statements = [self::statement('urn:example:weak'), self::statement('urn:example:strong')];

        self::assertSame(FailureReason::RESPONSE_INVALID, AuthenticationRules::context(self::assertion($statements), self::validation()));
    }

    /**
     * What the assembler answers for an ID token with the claims given, and
     * UserInfo answering as given when it does.
     *
     * @param  array<string, mixed>  $claims
     * @param  ?array<string, mixed>  $userInfo
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function assembled(array $claims, ?array $userInfo = null): Completion
    {
        if ($userInfo !== null) {
            $this->fetcher->respond(self::ENDPOINT, FakeTokenEndpoint::json(200, $userInfo));
        }

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $connection = new IdentifiedConnection(self::CONNECTION_ID, settings: ['fetch_userinfo' => $userInfo !== null, 'userinfo_endpoint' => self::ENDPOINT]);
        $consumed   = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(ExampleResults::REFERENCE), CarbonImmutable::parse('2026-11-01T09:28:00Z'));
        $tokens     = new TokenResponse('header.payload.signature', 'the-access-token');
        $idToken    = new ValidatedIdToken(self::ISSUER, self::SUBJECT, [
            'iss' => self::ISSUER,
            'sub' => self::SUBJECT,
            'aud' => 'the-client',
            'exp' => self::AUTHENTICATED_AT_SECONDS + 300,
            'iat' => self::AUTHENTICATED_AT_SECONDS,
            ...$claims,
        ]);

        return $app->make(ClaimsAssembler::class)->assemble($connection, OidcOptions::of($connection), $idToken, $tokens, $consumed);
    }

    /**
     * The result a verified completion gives.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Completion  $completion
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function resultOf(Completion $completion): VerifiedResult
    {
        self::assertNull($completion->reason);
        self::assertNotNull($completion->claims);

        return self::resultWith($completion->claims->authenticationContext);
    }

    /**
     * The package's policy, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy
     */
    private static function policy(): ConnectionEvidencePolicy
    {
        return app(ConnectionEvidencePolicy::class);
    }

    /**
     * The instant asked at: a minute after the provider authenticated.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function at(): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-11-01T09:30:00Z');
    }

    /**
     * A connection holding the policy, unsaved.
     *
     * @param  array<string, mixed>  $policy
     * @param  string  $protocol
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private static function connection(array $policy, string $protocol = 'oidc'): Connection
    {
        $connection = new Connection;

        $connection->forceFill(['id' => self::CONNECTION_ID, 'tenant_id' => 'tenant-1', 'protocol' => $protocol, 'evidence_policy' => $policy]);

        return $connection;
    }

    /**
     * A result with the context, of the connection unless it is told otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Results\AuthenticationContext  $context
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private static function resultWith(
        AuthenticationContext $context,
        Purpose $purpose = Purpose::SIGN_IN,
        string $connectionId = self::CONNECTION_ID,
        string $tenantId = 'tenant-1',
        string $protocol = 'oidc',
    ): VerifiedResult {
        return new VerifiedResult(
            issuer: self::ISSUER,
            subject: self::SUBJECT,
            nameIdFormat: null,
            connectionId: $connectionId,
            tenantId: $tenantId,
            protocol: $protocol,
            application: 'web',
            purpose: $purpose,
            requestReference: RequestReference::fromString(ExampleResults::REFERENCE),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: $context,
        );
    }

    /**
     * A statement of the class, a minute before the instant asked.
     *
     * @param  string  $class
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement
     */
    private static function statement(string $class): AuthnStatement
    {
        return new AuthnStatement(self::at()->subMinute(), '_session-1', self::at()->addHours(8), $class);
    }

    /**
     * An assertion with the statements.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement>  $statements
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function assertion(array $statements): SamlAssertion
    {
        return new SamlAssertion('_assertion-1', new NameId(self::ISSUER), self::at(), null, null, $statements);
    }

    /**
     * What a SAML assertion is validated against.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     */
    private static function validation(): ValidationContext
    {
        $options = Saml2Options::of(new ExampleConnection('saml2', ['idp_entity_id' => self::ISSUER]));

        return new ValidationContext(self::CONNECTION_ID, $options, 'https://sp.example.test/saml/acs', 'https://sp.example.test/saml/metadata', self::at(), 60, 300);
    }
}
