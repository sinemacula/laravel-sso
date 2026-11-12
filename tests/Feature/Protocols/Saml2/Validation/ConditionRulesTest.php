<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlStatus;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ConditionRules;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for the rules of a SAML assertion's conditions and
 * `IssueInstant`s.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConditionRules::class)]
#[CoversClass(ValidationContext::class)]
final class ConditionRulesTest extends TestCase
{
    /** @var string The identity provider's entity id. */
    private const string IDP = 'https://idp.example.test/saml';

    /** @var string The service provider's entity id. */
    private const string SP = 'https://sp.example.test/saml/metadata';

    /** @var string The assertion consumer service. */
    private const string ACS = 'https://sp.example.test/saml/acs';

    /** @var string The instant every rule is judged at. */
    private const string NOW = '2026-11-01T09:30:00Z';

    /** @var string An unknown condition's qualified name. */
    private const string UNKNOWN = '{urn:example:conditions}Custom';

    /**
     * An assertion within its conditions, for the service provider, issued now,
     * is accepted; so is one without conditions.
     *
     * @return void
     */
    public function testAcceptsAnAssertionWithinItsConditionsOrWithoutAny(): void
    {
        self::assertNull(self::refusal(new SamlConditions(self::at(-60), self::at(300), [[self::SP]], 1, 1)));
        self::assertNull(self::refusal(null));
        self::assertNull(self::refusal(new SamlConditions));
    }

    /**
     * Rows of `[notBefore, notOnOrAfter, reason]`: the conditions' bounds, in
     * seconds from now, and the refusal; the skew is 60 seconds.
     *
     * @return iterable<string, array{0: ?int, 1: ?int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideValidity(): iterable
    {
        yield from [
            'NotBefore at now plus the skew'           => [60, null, null],
            'NotBefore one second over'                => [61, null, FailureReason::ASSERTION_EXPIRED],
            'NotBefore one second under'               => [59, null, null],
            'NotOnOrAfter one second within the skew'  => [null, -59, null],
            'NotOnOrAfter exactly the skew ago'        => [null, -60, FailureReason::ASSERTION_EXPIRED],
            'NotOnOrAfter one second beyond the skew'  => [null, -61, FailureReason::ASSERTION_EXPIRED],
            'both bounds holding'                      => [-60, 300, null],
            'a window that has not started, nor ended' => [120, 300, FailureReason::ASSERTION_EXPIRED],
            'a window that started and ended'          => [-600, -120, FailureReason::ASSERTION_EXPIRED],
            'neither bound'                            => [null, null, null],
        ];
    }

    /**
     * `NotBefore` must not be after now plus the skew, and now must be before
     * `NotOnOrAfter` plus the skew.
     *
     * @param  ?int  $notBefore
     * @param  ?int  $notOnOrAfter
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideValidity')]
    public function testHoldsTheConditionsValidityWithTheSkew(?int $notBefore, ?int $notOnOrAfter, ?FailureReason $reason): void
    {
        self::assertSame($reason, self::refusal(new SamlConditions(self::at($notBefore), self::at($notOnOrAfter), [[self::SP]])));
    }

    /**
     * Rows of `[restrictions, reason]`: the audience restrictions, and the
     * refusal.
     *
     * @return iterable<string, array{0: list<list<string>>, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideAudiences(): iterable
    {
        yield from [
            'none'                                => [[], null],
            'one naming the service provider'     => [[[self::SP]], null],
            'one naming it among others'          => [[['https://other.example.test', self::SP]], null],
            'two, each naming it'                 => [[[self::SP], ['https://other.example.test', self::SP]], null],
            'two, the second not naming it'       => [[[self::SP], ['https://other.example.test']], FailureReason::AUDIENCE_MISMATCH],
            'two, the first not naming it'        => [[['https://other.example.test'], [self::SP]], FailureReason::AUDIENCE_MISMATCH],
            'an empty restriction'                => [[[]], FailureReason::AUDIENCE_MISMATCH],
            'an empty one beside one naming it'   => [[[self::SP], []], FailureReason::AUDIENCE_MISMATCH],
            'another audience'                    => [[['https://other.example.test']], FailureReason::AUDIENCE_MISMATCH],
            'the entity id in another case'       => [[[strtoupper(self::SP)]], FailureReason::AUDIENCE_MISMATCH],
            'the entity id with a trailing slash' => [[[self::SP . '/']], FailureReason::AUDIENCE_MISMATCH],
        ];
    }

    /**
     * Every audience restriction must name the service provider exactly.
     *
     * @param  list<list<string>>  $restrictions
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideAudiences')]
    public function testEveryAudienceRestrictionMustNameTheServiceProvider(array $restrictions, ?FailureReason $reason): void
    {
        self::assertSame($reason, self::refusal(new SamlConditions(null, null, $restrictions)));
    }

    /**
     * `OneTimeUse` and `ProxyRestriction` are accepted; any other condition is
     * refused.
     *
     * @return void
     */
    public function testRefusesEveryConditionItDoesNotUnderstand(): void
    {
        self::assertNull(self::refusal(new SamlConditions(null, null, [[self::SP]], 1, 2)));
        self::assertSame(FailureReason::CONDITION_UNSUPPORTED, self::refusal(new SamlConditions(null, null, [[self::SP]], 0, 0, [self::UNKNOWN])));
        self::assertSame(FailureReason::CONDITION_UNSUPPORTED, self::refusal(new SamlConditions(null, null, [], 1, 1, [self::UNKNOWN, self::UNKNOWN])));
    }

    /**
     * Rows of `[response, assertion, reason]`, each `IssueInstant` in seconds
     * from now, with a 60-second skew and 300-second maximum age.
     *
     * @return iterable<string, array{0: int, 1: int, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideIssueInstants(): iterable
    {
        yield from [
            'both now'                                  => [0, 0, null],
            'the response at now plus the skew'         => [60, 0, null],
            'the response one second further'           => [61, 0, FailureReason::ASSERTION_EXPIRED],
            'the assertion at now plus the skew'        => [0, 60, null],
            'the assertion one second further'          => [0, 61, FailureReason::ASSERTION_EXPIRED],
            'the response at the maximum age and skew'  => [-360, 0, null],
            'the response one second older'             => [-361, 0, FailureReason::ASSERTION_EXPIRED],
            'the response one second younger'           => [-359, 0, null],
            'the assertion at the maximum age and skew' => [0, -360, null],
            'the assertion one second older'            => [0, -361, FailureReason::ASSERTION_EXPIRED],
        ];
    }

    /**
     * The response's and the assertion's `IssueInstant` are each not after now
     * plus the skew, and no older than the maximum age plus the skew.
     *
     * @param  int  $response
     * @param  int  $assertion
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideIssueInstants')]
    public function testHoldsBothIssueInstantsToTheirMaximumAge(int $response, int $assertion, ?FailureReason $reason): void
    {
        self::assertSame($reason, self::refusal(null, $response, $assertion));
    }

    /**
     * The rules answer in order: window, audience, unknown condition, then
     * `IssueInstant`s.
     *
     * @return void
     */
    public function testAnswersInItsOrder(): void
    {
        $other = [['https://other.example.test']];

        self::assertSame(FailureReason::ASSERTION_EXPIRED, self::refusal(new SamlConditions(null, self::at(-600), $other, 0, 0, [self::UNKNOWN])));
        self::assertSame(FailureReason::AUDIENCE_MISMATCH, self::refusal(new SamlConditions(null, null, $other, 0, 0, [self::UNKNOWN]), -3600));
        self::assertSame(FailureReason::CONDITION_UNSUPPORTED, self::refusal(new SamlConditions(null, null, [], 0, 0, [self::UNKNOWN]), -3600));
    }

    /**
     * The skew and the maximum age are the context's.
     *
     * @return void
     */
    public function testReadsTheSkewAndMaximumAgeFromTheContext(): void
    {
        $context = self::context(0, 30);

        self::assertNull(ConditionRules::refusal(self::response(-30), self::assertion(new SamlConditions(null, self::at(1)), 0), $context));
        self::assertSame(FailureReason::ASSERTION_EXPIRED, ConditionRules::refusal(self::response(0), self::assertion(new SamlConditions(null, self::at(0)), 0), $context));
        self::assertSame(FailureReason::ASSERTION_EXPIRED, ConditionRules::refusal(self::response(-31), self::assertion(null, 0), $context));
        self::assertSame(FailureReason::ASSERTION_EXPIRED, ConditionRules::refusal(self::response(1), self::assertion(null, 0), $context));
    }

    /**
     * The refusal of a response issued at the offset whose assertion, with the
     * conditions, was issued at its own, both in seconds from now.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions  $conditions
     * @param  int  $response
     * @param  int  $assertion
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function refusal(?SamlConditions $conditions, int $response = 0, int $assertion = 0): ?FailureReason
    {
        return ConditionRules::refusal(self::response($response), self::assertion($conditions, $assertion), self::context());
    }

    /**
     * A successful response issued at the offset from now.
     *
     * @param  int  $offset
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse
     */
    private static function response(int $offset): SamlResponse
    {
        return new SamlResponse(ValidationProfile::SOLICITED, '_response-1', self::now()->addSeconds($offset), new SamlStatus(SamlStatus::SUCCESS));
    }

    /**
     * An assertion with the conditions, issued at the offset from now.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions  $conditions
     * @param  int  $offset
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function assertion(?SamlConditions $conditions, int $offset): SamlAssertion
    {
        return new SamlAssertion('_assertion-1', new NameId(self::IDP), self::now()->addSeconds($offset), null, $conditions);
    }

    /**
     * The context the rules are judged in: now, with the skew and maximum age
     * given.
     *
     * @param  int  $skew
     * @param  int  $maxAge
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     */
    private static function context(int $skew = 60, int $maxAge = 300): ValidationContext
    {
        $options = Saml2Options::of(new ExampleConnection('saml2', ['idp_entity_id' => self::IDP]));

        return new ValidationContext('01jbexampleconnection00000', $options, self::ACS, self::SP, self::now(), $skew, $maxAge);
    }

    /**
     * The instant the offset from now names, or `null` for none.
     *
     * @param  ?int  $offset
     * @return ?\Carbon\CarbonImmutable
     */
    private static function at(?int $offset): ?CarbonImmutable
    {
        return $offset === null ? null : self::now()->addSeconds($offset);
    }

    /**
     * The instant every rule is judged at.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function now(): CarbonImmutable
    {
        return CarbonImmutable::parse(self::NOW);
    }
}
