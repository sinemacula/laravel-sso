<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AuthenticationRules;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for the authentication a verified SAML assertion states.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationRules::class)]
#[CoversClass(ValidationContext::class)]
final class AuthenticationRulesTest extends TestCase
{
    /** @var string The identity provider's entity id. */
    private const string IDP = 'https://idp.example.test/saml';

    /** @var string The password-protected-transport class. */
    private const string PPT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

    /** @var string The multi-factor class a connection may require. */
    private const string MFA = 'https://refeds.org/profile/mfa';

    /**
     * The one statement maps to the authentication context: its instant, class,
     * session index and session deadline, exactly.
     *
     * @return void
     */
    public function testMapsTheOneStatementToTheAuthenticationContext(): void
    {
        $context = AuthenticationRules::context(self::assertion([self::statement()]), self::context());

        self::assertInstanceOf(AuthenticationContext::class, $context);
        self::assertSame([
            'authenticated_at'          => '2026-11-01T09:29:00.000000Z',
            'methods'                   => [],
            'context_class'             => self::PPT,
            'provider_session_id'       => '_session-1',
            'provider_session_deadline' => '2026-11-01T17:30:00.000000Z',
        ], $context->toArray());
    }

    /**
     * A statement with neither a class, a session index nor a deadline maps to
     * a context without them.
     *
     * @return void
     */
    public function testMapsAStatementWithoutItsOptionalParts(): void
    {
        $context = AuthenticationRules::context(self::assertion([new AuthnStatement(self::now()->subMinute())]), self::context());

        self::assertInstanceOf(AuthenticationContext::class, $context);
        self::assertSame(['2026-11-01T09:29:00.000000Z', null, null, null], [
            $context->toArray()['authenticated_at'], $context->contextClass, $context->providerSessionId, $context->providerSessionDeadline,
        ]);
    }

    /**
     * No statement and two statements are each refused.
     *
     * @return void
     */
    public function testRequiresExactlyOneStatement(): void
    {
        self::assertSame(FailureReason::RESPONSE_INVALID, AuthenticationRules::context(self::assertion([]), self::context()));
        self::assertSame(FailureReason::RESPONSE_INVALID, AuthenticationRules::context(self::assertion([self::statement(), self::statement()]), self::context()));
    }

    /**
     * Rows of `[sessionIndex, class, accepted]`: a session index and a class,
     * and whether the context can hold them.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: bool}>
     */
    public static function provideStoredLengths(): iterable
    {
        yield from [
            'a session index of 1024 bytes' => [str_repeat('s', 1024), null, true],
            'a session index of 1025 bytes' => [str_repeat('s', 1025), null, false],
            'an empty session index'        => ['', null, false],
            'a class of 1024 bytes'         => [null, str_repeat('c', 1024), true],
            'a class of 1025 bytes'         => [null, str_repeat('c', 1025), false],
            'an empty class'                => [null, '', false],
            'a session index of one byte'   => ['s', 'c', true],
        ];
    }

    /**
     * A session index or class the authentication context cannot hold refuses
     * the response, rather than failing as a server error.
     *
     * @param  ?string  $sessionIndex
     * @param  ?string  $class
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideStoredLengths')]
    public function testRefusesWhatTheContextCannotHold(?string $sessionIndex, ?string $class, bool $accepted): void
    {
        $context = AuthenticationRules::context(self::assertion([new AuthnStatement(self::now(), $sessionIndex, null, $class)]), self::context());

        self::assertSame($accepted, $context instanceof AuthenticationContext);
        self::assertSame($accepted ? $sessionIndex : FailureReason::RESPONSE_INVALID, $context instanceof AuthenticationContext ? $context->providerSessionId : $context);
    }

    /**
     * Rows of `[instant, maxAge, reason]`, the instant in seconds from now,
     * with a 60-second skew.
     *
     * @return iterable<string, array{0: int, 1: ?int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideInstants(): iterable
    {
        yield from [
            'now plus the skew'                          => [60, null, null],
            'one second beyond the skew'                 => [61, null, FailureReason::ASSERTION_EXPIRED],
            'a week ago, no maximum age'                 => [-604800, null, null],
            'the maximum age and the skew ago'           => [-3660, 3600, null],
            'one second less than that'                  => [-3659, 3600, null],
            'one second more than that'                  => [-3661, 3600, FailureReason::AUTHENTICATION_EXPIRED],
            'in the future beyond the skew, with an age' => [61, 3600, FailureReason::ASSERTION_EXPIRED],
        ];
    }

    /**
     * The `AuthnInstant` may not be after now plus the skew, and, with a
     * maximum authentication age, no older than it plus the skew.
     *
     * @param  int  $instant
     * @param  ?int  $maxAge
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideInstants')]
    public function testHoldsTheInstantToTheSkewAndTheMaximumAge(int $instant, ?int $maxAge, ?FailureReason $reason): void
    {
        $settings = $maxAge === null ? [] : ['max_authentication_age_seconds' => $maxAge];
        $context  = AuthenticationRules::context(self::assertion([new AuthnStatement(self::now()->addSeconds($instant))]), self::context($settings));

        self::assertSame($reason, $context instanceof FailureReason ? $context : null);
    }

    /**
     * Rows of `[purpose, instant, reason]`, the instant in seconds from a start
     * ten minutes ago.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideReauthentication(): iterable
    {
        yield from [
            'reauthenticate, at the start less the skew' => [Purpose::REAUTHENTICATE, -60, null],
            'reauthenticate, one second earlier'         => [Purpose::REAUTHENTICATE, -61, FailureReason::AUTHENTICATION_EXPIRED],
            'reauthenticate, one second later'           => [Purpose::REAUTHENTICATE, -59, null],
            'reauthenticate, after the start'            => [Purpose::REAUTHENTICATE, 300, null],
            'sign in, long before the start'             => [Purpose::SIGN_IN, -86400, null],
            'link, long before the start'                => [Purpose::LINK, -86400, null],
        ];
    }

    /**
     * A `reauthenticate` request needs an authentication no earlier than its
     * start less the skew; any other purpose does not.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  int  $instant
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideReauthentication')]
    public function testAReauthenticationMustFollowTheRequestsStart(Purpose $purpose, int $instant, ?FailureReason $reason): void
    {
        $started   = self::now()->subMinutes(10);
        $consumed  = new ConsumedRequest($purpose, 'web', RequestReference::fromString('Bq8tVv3w0kLmNoPqRsTuVwXyZ0123456'), $started, samlRequestId: '_request-1');
        $statement = new AuthnStatement($started->addSeconds($instant));
        $context   = AuthenticationRules::context(self::assertion([$statement]), self::context([], $consumed));

        self::assertSame($reason, $context instanceof FailureReason ? $context : null);
        self::assertInstanceOf(AuthenticationContext::class, AuthenticationRules::context(self::assertion([$statement]), self::context()));
    }

    /**
     * Rows of `[required, class, reason]`: the classes the connection requires,
     * the statement's, and the refusal.
     *
     * @return iterable<string, array{0: list<string>, 1: ?string, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideClasses(): iterable
    {
        yield from [
            'none required, any class'  => [[], 'urn:example:anything', null],
            'none required, no class'   => [[], null, null],
            'the one required'          => [[self::MFA], self::MFA, null],
            'one of those required'     => [[self::PPT, self::MFA], self::MFA, null],
            'another class'             => [[self::MFA], self::PPT, FailureReason::AUTHENTICATION_CONTEXT_MISMATCH],
            'no class'                  => [[self::MFA], null, FailureReason::AUTHENTICATION_CONTEXT_MISMATCH],
            'the class in another case' => [[self::MFA], strtoupper(self::MFA), FailureReason::AUTHENTICATION_CONTEXT_MISMATCH],
        ];
    }

    /**
     * With classes required, the statement's must be one of them exactly.
     *
     * @param  list<string>  $required
     * @param  ?string  $class
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideClasses')]
    public function testARequiredClassMustBeAsserted(array $required, ?string $class, ?FailureReason $reason): void
    {
        $context = AuthenticationRules::context(self::assertion([new AuthnStatement(self::now(), null, null, $class)]), self::context(['requested_authn_context' => $required]));

        self::assertSame($reason, $context instanceof FailureReason ? $context : null);
    }

    /**
     * Rows of `[deadline, reason]`: the `SessionNotOnOrAfter` in seconds from
     * now, and the refusal; the skew never extends it.
     *
     * @return iterable<string, array{0: int, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideDeadlines(): iterable
    {
        yield from [
            'one second from now'         => [1, null],
            'now'                         => [0, FailureReason::AUTHENTICATION_EXPIRED],
            'one second ago'              => [-1, FailureReason::AUTHENTICATION_EXPIRED],
            'within what the skew allows' => [-30, FailureReason::AUTHENTICATION_EXPIRED],
        ];
    }

    /**
     * A provider session that has ended refuses the response; one that has not
     * is the context's deadline.
     *
     * @param  int  $deadline
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideDeadlines')]
    public function testAnEndedProviderSessionIsRefused(int $deadline, ?FailureReason $reason): void
    {
        $instant = self::now()->addSeconds($deadline);
        $context = AuthenticationRules::context(self::assertion([new AuthnStatement(self::now(), null, $instant)]), self::context());

        self::assertSame($reason ?? $instant->toIso8601String(), $context instanceof AuthenticationContext ? $context->providerSessionDeadline?->toIso8601String() : $context);
    }

    /**
     * The rules answer in order: context, future instant, maximum age,
     * reauthentication, class, session.
     *
     * @return void
     */
    public function testAnswersInItsOrder(): void
    {
        $strict   = self::context(['max_authentication_age_seconds' => 60, 'requested_authn_context' => [self::MFA]]);
        $ended    = self::now()->subSecond();
        $old      = self::now()->subHour();
        $consumed = new ConsumedRequest(Purpose::REAUTHENTICATE, 'web', RequestReference::fromString('Bq8tVv3w0kLmNoPqRsTuVwXyZ0123456'), self::now(), samlRequestId: '_r');
        $reauth   = self::context(['requested_authn_context' => [self::MFA]], $consumed);

        self::assertSame(FailureReason::RESPONSE_INVALID, self::refusalOf(new AuthnStatement(self::now()->addHour(), '', $ended, self::PPT), $strict));
        self::assertSame(FailureReason::ASSERTION_EXPIRED, self::refusalOf(new AuthnStatement(self::now()->addHour(), null, $ended, self::PPT), $strict));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, self::refusalOf(new AuthnStatement($old, null, null, self::PPT), $strict));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, self::refusalOf(new AuthnStatement($old, null, null, self::PPT), $reauth));
        self::assertSame(FailureReason::AUTHENTICATION_CONTEXT_MISMATCH, self::refusalOf(new AuthnStatement(self::now(), null, $ended, self::PPT), $strict));
        self::assertSame(FailureReason::AUTHENTICATION_EXPIRED, self::refusalOf(new AuthnStatement(self::now(), null, $ended, self::MFA), $strict));
    }

    /**
     * What the rules answer for an assertion with the one statement.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement  $statement
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return \SineMacula\Laravel\Sso\Events\Enums\FailureReason|\SineMacula\Laravel\Sso\Results\AuthenticationContext
     */
    private static function refusalOf(AuthnStatement $statement, ValidationContext $context): AuthenticationContext|FailureReason
    {
        return AuthenticationRules::context(self::assertion([$statement]), $context);
    }

    /**
     * The default statement: a minute old, with a session index, an eight-hour
     * deadline and the password-protected-transport class.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement
     */
    private static function statement(): AuthnStatement
    {
        return new AuthnStatement(self::now()->subMinute(), '_session-1', self::now()->addHours(8), self::PPT);
    }

    /**
     * An assertion with the statements.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement>  $statements
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function assertion(array $statements): SamlAssertion
    {
        return new SamlAssertion('_assertion-1', new NameId(self::IDP), self::now(), null, null, $statements);
    }

    /**
     * The context of a connection with the settings given, for the consumed
     * request, or by the unsolicited profile.
     *
     * @param  array<string, mixed>  $settings
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     */
    private static function context(array $settings = [], ?ConsumedRequest $consumed = null): ValidationContext
    {
        $options = Saml2Options::of(new ExampleConnection('saml2', ['idp_entity_id' => self::IDP, ...$settings]));

        $acs = 'https://sp.example.test/saml/acs';

        return new ValidationContext('01jbexampleconnection00000', $options, $acs, 'https://sp.example.test/saml/metadata', self::now(), 60, 300, $consumed);
    }

    /**
     * The instant every rule is judged at.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function now(): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-11-01T09:30:00Z');
    }
}
