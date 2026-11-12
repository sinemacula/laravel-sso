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
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlStatus;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlSubject;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\BearerConfirmations;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for the bearer confirmation a SAML assertion is accepted by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerConfirmations::class)]
#[CoversClass(ValidationContext::class)]
final class BearerConfirmationsTest extends TestCase
{
    /** @var string The identity provider's entity id. */
    private const string IDP = 'https://idp.example.test/saml';

    /** @var string The service provider's entity id. */
    private const string SP = 'https://sp.example.test/saml/metadata';

    /** @var string The assertion consumer service. */
    private const string ACS = 'https://sp.example.test/saml/acs';

    /** @var string The SAML request id of the consumed request. */
    private const string REQUEST_ID = '_request-1';

    /** @var string The holder-of-key confirmation method. */
    private const string HOLDER_OF_KEY = 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key';

    /**
     * A bearer confirmation that satisfies every rule is the one chosen, for
     * the consumed request, and for the unsolicited profile without one.
     *
     * @return void
     */
    public function testChoosesTheConfirmationThatSatisfiesEveryRule(): void
    {
        $confirmation = self::confirmation();
        $unsolicited  = self::confirmation(['in_response_to' => null]);

        self::assertSame($confirmation, self::chosen([$confirmation]));
        self::assertSame($unsolicited, BearerConfirmations::chosen(self::response(null), self::assertion([$unsolicited]), self::context(false)));
    }

    /**
     * Rows of `[responseInResponseTo, solicited, reason]`: the response's own
     * `InResponseTo`, whether a request was consumed, and the refusal.
     *
     * @return iterable<string, array{0: ?string, 1: bool, 2: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideResponseInResponseTo(): iterable
    {
        yield from [
            'the consumed request'         => [self::REQUEST_ID, true, null],
            'another request'              => ['_request-2', true, FailureReason::REQUEST_MISMATCH],
            'the request in another case'  => [strtoupper(self::REQUEST_ID), true, FailureReason::REQUEST_MISMATCH],
            'none, for a consumed request' => [null, true, FailureReason::REQUEST_MISMATCH],
            'none, unsolicited'            => [null, false, null],
            'a request, unsolicited'       => [self::REQUEST_ID, false, FailureReason::REQUEST_MISMATCH],
        ];
    }

    /**
     * The response's own `InResponseTo` must be the consumed request's id, or
     * absent for the unsolicited profile, whatever its confirmations say.
     *
     * @param  ?string  $inResponseTo
     * @param  bool  $solicited
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideResponseInResponseTo')]
    public function testTheResponsesInResponseToMustAnswerTheConsumedRequest(?string $inResponseTo, bool $solicited, ?FailureReason $reason): void
    {
        $confirmation = self::confirmation(['in_response_to' => $solicited ? self::REQUEST_ID : null]);
        $context      = self::context($solicited);
        $chosen       = BearerConfirmations::chosen(self::response($inResponseTo), self::assertion([$confirmation]), $context);

        self::assertSame($reason ?? $confirmation, $chosen);
        self::assertSame($reason === null, BearerConfirmations::isAnswer(self::response($inResponseTo), $context));
    }

    /**
     * Rows of `[changes, reason]`: a bearer confirmation's change from one that
     * satisfies every rule, and the refusal; the skew is 60 seconds.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideConfirmationRules(): iterable
    {
        yield from [
            'no data'                                 => [['data' => false], FailureReason::RECIPIENT_MISMATCH],
            'no recipient'                            => [['recipient' => null], FailureReason::RECIPIENT_MISMATCH],
            'another recipient'                       => [['recipient' => 'https://sp.example.test/other'], FailureReason::RECIPIENT_MISMATCH],
            'the recipient with a trailing slash'     => [['recipient' => self::ACS . '/'], FailureReason::RECIPIENT_MISMATCH],
            'no NotOnOrAfter'                         => [['not_on_or_after' => null], FailureReason::ASSERTION_EXPIRED],
            'NotOnOrAfter one second within the skew' => [['not_on_or_after' => -59], null],
            'NotOnOrAfter exactly the skew ago'       => [['not_on_or_after' => -60], FailureReason::ASSERTION_EXPIRED],
            'NotOnOrAfter one second beyond the skew' => [['not_on_or_after' => -61], FailureReason::ASSERTION_EXPIRED],
            'a NotBefore in the past'                 => [['not_before' => -60], FailureReason::ASSERTION_EXPIRED],
            'a NotBefore now'                         => [['not_before' => 0], FailureReason::ASSERTION_EXPIRED],
            'no InResponseTo'                         => [['in_response_to' => null], FailureReason::REQUEST_MISMATCH],
            'another InResponseTo'                    => [['in_response_to' => '_request-2'], FailureReason::REQUEST_MISMATCH],
        ];
    }

    /**
     * One bearer confirmation must satisfy every rule on its own.
     *
     * @param  array<string, mixed>  $changes
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideConfirmationRules')]
    public function testOneConfirmationMustSatisfyEveryRule(array $changes, ?FailureReason $reason): void
    {
        $confirmation = self::confirmation($changes);

        self::assertSame($reason ?? $confirmation, self::chosen([$confirmation]));
    }

    /**
     * For the unsolicited profile a confirmation must carry no `InResponseTo`.
     *
     * @return void
     */
    public function testAnUnsolicitedConfirmationMustAnswerNoRequest(): void
    {
        $answering = self::confirmation();

        self::assertSame(FailureReason::REQUEST_MISMATCH, BearerConfirmations::chosen(self::response(null), self::assertion([$answering]), self::context(false)));
    }

    /**
     * Only bearer confirmations count, and anything else is
     * `recipient_mismatch`.
     *
     * @return void
     */
    public function testOnlyBearerConfirmationsCount(): void
    {
        $holderOfKey = self::confirmation(['method' => self::HOLDER_OF_KEY]);
        $bearer      = self::confirmation();
        $noSubject   = new SamlAssertion('_assertion-1', new NameId(self::IDP), self::now());

        self::assertSame(FailureReason::RECIPIENT_MISMATCH, BearerConfirmations::chosen(self::response(), $noSubject, self::context()));
        self::assertSame(FailureReason::RECIPIENT_MISMATCH, self::chosen([]));
        self::assertSame(FailureReason::RECIPIENT_MISMATCH, self::chosen([$holderOfKey]));
        self::assertSame($bearer, self::chosen([$holderOfKey, $bearer]));
    }

    /**
     * A bearer confirmation naming another request is `request_mismatch` even
     * beside one that satisfies every rule.
     *
     * @return void
     */
    public function testNoBearerConfirmationMayNameAnotherRequest(): void
    {
        $answer = self::confirmation();
        $other  = self::confirmation(['in_response_to' => '_request-2']);
        $cased  = self::confirmation(['in_response_to' => '_REQUEST-1']);
        $none   = self::confirmation(['in_response_to' => null]);
        $holder = self::confirmation(['method' => self::HOLDER_OF_KEY, 'in_response_to' => '_request-2']);

        self::assertSame(FailureReason::REQUEST_MISMATCH, self::chosen([$answer, $other]));
        self::assertSame(FailureReason::REQUEST_MISMATCH, self::chosen([$other, $answer]));
        self::assertSame(FailureReason::REQUEST_MISMATCH, self::chosen([$answer, $cased]));
        self::assertSame($answer, self::chosen([$answer, $none]));
        self::assertSame($answer, self::chosen([$none, $answer]));
        self::assertSame($answer, self::chosen([$holder, $answer]));
    }

    /**
     * Two confirmations that each satisfy only some rules are never combined.
     *
     * @return void
     */
    public function testNeverCombinesConfirmations(): void
    {
        $recipient = self::confirmation(['not_on_or_after' => null]);
        $expiry    = self::confirmation(['recipient' => 'https://sp.example.test/other']);

        self::assertSame(FailureReason::ASSERTION_EXPIRED, self::chosen([$recipient, $expiry]));
        self::assertSame(FailureReason::ASSERTION_EXPIRED, self::chosen([$expiry, $recipient]));
    }

    /**
     * Rows of `[changes, reason]`: two failing confirmations, and the reason of
     * the one that got further, whichever comes first.
     *
     * @return iterable<string, array{0: list<array<string, mixed>>, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideFurthest(): iterable
    {
        $recipient   = ['recipient' => 'https://sp.example.test/other'];
        $expired     = ['not_on_or_after' => -600];
        $notBefore   = ['not_before' => -60];
        $unanswering = ['in_response_to' => '_request-2'];

        yield from [
            'a wrong recipient, then expired'    => [[$recipient, $expired], FailureReason::ASSERTION_EXPIRED],
            'expired, then a wrong recipient'    => [[$expired, $recipient], FailureReason::ASSERTION_EXPIRED],
            'expired, then a NotBefore'          => [[$expired, $notBefore], FailureReason::ASSERTION_EXPIRED],
            'a NotBefore, then another request'  => [[$notBefore, $unanswering], FailureReason::REQUEST_MISMATCH],
            'another request, then a NotBefore'  => [[$unanswering, $notBefore], FailureReason::REQUEST_MISMATCH],
            'another request, then no recipient' => [[$unanswering, $recipient], FailureReason::REQUEST_MISMATCH],
            'two wrong recipients'               => [[$recipient, ['data' => false]], FailureReason::RECIPIENT_MISMATCH],
        ];
    }

    /**
     * With no confirmation satisfying every rule, the refusal is the reason of
     * the rule the furthest one broke.
     *
     * @param  list<array<string, mixed>>  $changes
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideFurthest')]
    public function testAnswersTheReasonOfTheFurthestConfirmation(array $changes, FailureReason $reason): void
    {
        self::assertSame($reason, self::chosen(array_map(self::confirmation(...), $changes)));
    }

    /**
     * Of the confirmations that satisfy every rule, the latest to expire is
     * chosen, the first on a tie, wherever a failing one stands.
     *
     * @return void
     */
    public function testChoosesTheLatestToExpireThenTheFirst(): void
    {
        $early  = self::confirmation(['not_on_or_after' => 120]);
        $late   = self::confirmation(['not_on_or_after' => 600]);
        $tied   = self::confirmation(['not_on_or_after' => 600]);
        $failed = self::confirmation(['not_before' => 0, 'not_on_or_after' => 3600]);

        self::assertSame($late, self::chosen([$early, $late]));
        self::assertSame($late, self::chosen([$late, $early]));
        self::assertSame($late, self::chosen([$late, $tied]));
        self::assertSame($tied, self::chosen([$tied, $late]));
        self::assertSame($early, self::chosen([$failed, $early]));
        self::assertSame($early, self::chosen([$early, $failed]));
    }

    /**
     * Confirmation expiries are compared to the microsecond, and only an exact
     * tie goes to the first.
     *
     * @return void
     */
    public function testComparesExpiriesToTheMicrosecond(): void
    {
        $whole = self::ending(self::now()->addSeconds(300));
        $tied  = self::ending(self::now()->addSeconds(300));
        $half  = self::ending(self::now()->addSeconds(300)->addMicroseconds(500000));
        $next  = self::ending(self::now()->addSeconds(300)->addMicrosecond());

        self::assertSame($half, self::chosen([$whole, $half]));
        self::assertSame($half, self::chosen([$half, $whole]));
        self::assertSame($next, self::chosen([$whole, $next]));
        self::assertSame($next, self::chosen([$next, $whole]));
        self::assertSame($whole, self::chosen([$whole, $tied]));
        self::assertSame($tied, self::chosen([$tied, $whole]));
    }

    /**
     * The skew is the context's: with none, a confirmation expires exactly at
     * its `NotOnOrAfter`.
     *
     * @return void
     */
    public function testReadsTheSkewFromTheContext(): void
    {
        $context = self::context(true, 0);
        $live    = self::confirmation(['not_on_or_after' => 1]);
        $ended   = self::confirmation(['not_on_or_after' => 0]);

        self::assertSame($live, BearerConfirmations::chosen(self::response(), self::assertion([$live]), $context));
        self::assertSame(FailureReason::ASSERTION_EXPIRED, BearerConfirmations::chosen(self::response(), self::assertion([$ended]), $context));
    }

    /**
     * The confirmation chosen from those given, for the consumed request, or
     * why none is.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation>  $confirmations
     * @return \SineMacula\Laravel\Sso\Events\Enums\FailureReason|\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation
     */
    private static function chosen(array $confirmations): FailureReason|SubjectConfirmation
    {
        return BearerConfirmations::chosen(self::response(), self::assertion($confirmations), self::context());
    }

    /**
     * A bearer confirmation that satisfies every rule for the consumed request,
     * with the changes given, each instant in seconds from now.
     *
     * @param  array<string, mixed>  $changes
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation
     */
    private static function confirmation(array $changes = []): SubjectConfirmation
    {
        /** @var array{method: string, data: bool, not_before: ?int, not_on_or_after: ?int, recipient: ?string, in_response_to: ?string} $values */
        $values = [
            'method'          => SubjectConfirmation::BEARER,
            'data'            => true,
            'not_before'      => null,
            'not_on_or_after' => 300,
            'recipient'       => self::ACS,
            'in_response_to'  => self::REQUEST_ID,
            ...$changes,
        ];

        return new SubjectConfirmation(
            $values['method'],
            $values['data'],
            $values['not_before']      === null ? null : self::now()->addSeconds($values['not_before']),
            $values['not_on_or_after'] === null ? null : self::now()->addSeconds($values['not_on_or_after']),
            $values['recipient'],
            $values['in_response_to'],
        );
    }

    /**
     * A bearer confirmation that satisfies every rule for the consumed request,
     * ending at the instant given.
     *
     * @param  \Carbon\CarbonImmutable  $notOnOrAfter
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation
     */
    private static function ending(CarbonImmutable $notOnOrAfter): SubjectConfirmation
    {
        return new SubjectConfirmation(SubjectConfirmation::BEARER, true, null, $notOnOrAfter, self::ACS, self::REQUEST_ID);
    }

    /**
     * A successful response answering the request named.
     *
     * @param  ?string  $inResponseTo
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse
     */
    private static function response(?string $inResponseTo = self::REQUEST_ID): SamlResponse
    {
        return new SamlResponse(ValidationProfile::SOLICITED, '_response-1', self::now(), new SamlStatus(SamlStatus::SUCCESS), ['in_response_to' => $inResponseTo]);
    }

    /**
     * An assertion whose subject carries the confirmations.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation>  $confirmations
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function assertion(array $confirmations): SamlAssertion
    {
        return new SamlAssertion('_assertion-1', new NameId(self::IDP), self::now(), new SamlSubject(IdentifierKind::NAME_ID, new NameId('alice'), $confirmations));
    }

    /**
     * The request consumed for the response.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     */
    private static function consumed(): ConsumedRequest
    {
        $reference = RequestReference::fromString('Bq8tVv3w0kLmNoPqRsTuVwXyZ0123456');

        return new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, self::now()->subMinute(), samlRequestId: self::REQUEST_ID);
    }

    /**
     * The context the confirmations are judged in: for the consumed request, or
     * by the unsolicited profile, with the skew.
     *
     * @param  bool  $solicited
     * @param  int  $skew
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     */
    private static function context(bool $solicited = true, int $skew = 60): ValidationContext
    {
        $options = Saml2Options::of(new ExampleConnection('saml2', ['idp_entity_id' => self::IDP]));

        return new ValidationContext('01jbexampleconnection00000', $options, self::ACS, self::SP, self::now(), $skew, 300, $solicited ? self::consumed() : null);
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
