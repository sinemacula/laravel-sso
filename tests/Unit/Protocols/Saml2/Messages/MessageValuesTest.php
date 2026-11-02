<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Saml2\Messages;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Envelope;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ReadResult;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlStatus;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlSubject;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * Unit tests for the SAML adapter's values (SSO-6.3, SSO-9.8, SSO-11.9): each
 * holds what the provider asserted behind its accessors, never shows a value to
 * a dump, an array cast or `json_encode()`, and refuses to be serialised; the
 * envelope's request id; the read result; and the response policy, which asks
 * for its keys only when called.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NameId::class)]
#[CoversClass(SubjectConfirmation::class)]
#[CoversClass(SamlConditions::class)]
#[CoversClass(AuthnStatement::class)]
#[CoversClass(SamlAttribute::class)]
#[CoversClass(SamlSubject::class)]
#[CoversClass(SamlAssertion::class)]
#[CoversClass(SamlStatus::class)]
#[CoversClass(SamlResponse::class)]
#[CoversClass(Envelope::class)]
#[CoversClass(ReadResult::class)]
#[CoversClass(ResponsePolicy::class)]
final class MessageValuesTest extends TestCase
{
    /** @var string A value no dump may show. */
    private const string SECRET = 'provider-asserted-value';

    /**
     * Rows of `[value]`: one of each value that holds what the provider
     * asserted, each holding the secret value.
     *
     * @return iterable<string, array{0: object}>
     */
    public static function provideHolders(): iterable
    {
        $now = CarbonImmutable::parse('2026-11-01T12:00:00Z');

        yield from [
            'name id'      => [new NameId(self::SECRET)],
            'confirmation' => [new SubjectConfirmation(SubjectConfirmation::BEARER, true, null, $now, self::SECRET)],
            'conditions'   => [new SamlConditions(null, null, [[self::SECRET]])],
            'statement'    => [new AuthnStatement($now, self::SECRET)],
            'attribute'    => [new SamlAttribute('email', null, null, [self::SECRET])],
            'subject'      => [new SamlSubject(IdentifierKind::NAME_ID, new NameId(self::SECRET))],
            'assertion'    => [new SamlAssertion('_a', new NameId(self::SECRET), $now)],
            'status'       => [new SamlStatus(SamlStatus::SUCCESS, null, self::SECRET)],
            'response'     => [new SamlResponse(ValidationProfile::SOLICITED, '_r', $now, new SamlStatus(SamlStatus::SUCCESS), ['in_response_to' => self::SECRET])],
            'envelope'     => [new Envelope([self::SECRET], true)],
        ];
    }

    /**
     * No dump, array cast or JSON encoding shows a value, and the value refuses
     * to be serialised and unserialised.
     *
     * @param  object  $value
     * @return void
     */
    #[DataProvider('provideHolders')]
    public function testAValueNeverShowsWhatTheProviderAsserted(object $value): void
    {
        self::assertSame(['values' => '[redacted]'], $value->__debugInfo()); // @phpstan-ignore method.notFound
        self::assertSame('{"values":"[redacted]"}', json_encode($value));
        self::assertStringNotContainsString(self::SECRET, print_r($value, true));
        self::assertStringNotContainsString(self::SECRET, var_export((array) $value, true));
    }

    /**
     * A value refuses to be serialised.
     *
     * @param  object  $value
     * @return void
     */
    #[DataProvider('provideHolders')]
    public function testAValueRefusesToBeSerialized(object $value): void
    {
        $this->expectExceptionObject(new \LogicException(sprintf('A %s cannot be serialised.', $value::class)));

        serialize($value);
    }

    /**
     * A value refuses to be unserialised.
     *
     * @param  object  $value
     * @return void
     */
    #[DataProvider('provideHolders')]
    public function testAValueRefusesToBeUnserialized(object $value): void
    {
        $this->expectExceptionObject(new \LogicException(sprintf('A %s cannot be unserialised.', $value::class)));

        $value->__unserialize([]); // @phpstan-ignore method.notFound
    }

    /**
     * Each accessor answers what it was given, and what was not given is
     * absent, never empty.
     *
     * @return void
     */
    public function testEachValueAnswersWhatItWasGiven(): void
    {
        $now          = CarbonImmutable::parse('2026-11-01T12:00:00Z');
        $nameId       = new NameId('alice', 'format', 'qualifier', 'sp-qualifier', 'provided');
        $confirmation = new SubjectConfirmation('urn:other');
        $assertion    = new SamlAssertion('_a', $nameId, $now);

        $bare      = new NameId('bob');
        $statement = new AuthnStatement($now);
        $attribute = new SamlAttribute('name');
        $subject   = new SamlSubject(IdentifierKind::NONE);

        self::assertSame(
            ['alice', 'format', 'qualifier', 'sp-qualifier', 'provided'],
            [$nameId->value(), $nameId->format(), $nameId->nameQualifier(), $nameId->spNameQualifier(), $nameId->spProvidedId()],
        );
        self::assertSame([null, null, null, null], [$bare->format(), $bare->nameQualifier(), $bare->spNameQualifier(), $bare->spProvidedId()]);
        self::assertSame(['urn:other', false, false, null, null, null, null, null], [
            $confirmation->method(), $confirmation->isBearer(), $confirmation->hasData(), $confirmation->notBefore(),
            $confirmation->notOnOrAfter(), $confirmation->recipient(), $confirmation->inResponseTo(), $confirmation->address(),
        ]);
        self::assertSame([null, null, [], 0, 0, []], [
            (new SamlConditions)->notBefore(), (new SamlConditions)->notOnOrAfter(), (new SamlConditions)->audienceRestrictions(),
            (new SamlConditions)->oneTimeUse(), (new SamlConditions)->proxyRestrictions(), (new SamlConditions)->otherConditions(),
        ]);
        self::assertSame([null, null, null], [$statement->sessionIndex(), $statement->sessionNotOnOrAfter(), $statement->contextClassRef()]);
        self::assertSame(['name', null, null, []], [$attribute->name(), $attribute->nameFormat(), $attribute->friendlyName(), $attribute->values()]);
        self::assertSame([IdentifierKind::NONE, null, []], [$subject->kind(), $subject->nameId(), $subject->confirmations()]);
        self::assertSame(['_a', $nameId, $now, null, null, [], [], 0, [], false, false, false], [
            $assertion->id(), $assertion->issuer(), $assertion->issueInstant(), $assertion->subject(),
            $assertion->conditions(), $assertion->authnStatements(), $assertion->attributes(), $assertion->encryptedAttributes(),
            $assertion->otherStatements(), $assertion->hasAdvice(), $assertion->isSigned(), $assertion->isEncrypted(),
        ]);
    }

    /**
     * A response's envelope parts are absent unless given, and it is unsigned
     * with no assertion unless it says otherwise.
     *
     * @return void
     */
    public function testAResponseHoldsItsEnvelope(): void
    {
        $now      = CarbonImmutable::parse('2026-11-01T12:00:00Z');
        $status   = new SamlStatus('urn:oasis:names:tc:SAML:2.0:status:Requester', 'sub', 'message');
        $response = new SamlResponse(ValidationProfile::UNSUCCESSFUL, '_r', $now, $status);

        self::assertSame([ValidationProfile::UNSUCCESSFUL, '_r', $now, $status, null, null, null, false, null], [
            $response->profile(), $response->id(), $response->issueInstant(), $response->status(), $response->issuer(),
            $response->destination(), $response->inResponseTo(), $response->isSigned(), $response->assertion(),
        ]);
        self::assertSame([false, 'sub', 'message'], [$status->isSuccess(), $status->subCode(), $status->message()]);
        self::assertTrue((new SamlStatus(SamlStatus::SUCCESS))->isSuccess());
        self::assertFalse((new SamlStatus(SamlStatus::SUCCESS . ' '))->isSuccess());
    }

    /**
     * Rows of `[inResponseTo, requestId, unsolicited]`: an envelope's
     * `InResponseTo`s, the one request id they name, and whether it is
     * unsolicited.
     *
     * @return iterable<string, array{0: list<string>, 1: ?string, 2: bool}>
     */
    public static function provideEnvelopes(): iterable
    {
        yield from [
            'none'            => [[], null, true],
            'one'             => [['_a'], '_a', false],
            'two that agree'  => [['_a', '_a'], '_a', false],
            'two that differ' => [['_a', '_b'], null, false],
            'differ by case'  => [['_a', '_A'], null, false],
            'three, one off'  => [['_a', '_a', '_b'], null, false],
        ];
    }

    /**
     * An envelope names one request only when every `InResponseTo` agrees,
     * compared exactly, and is unsolicited only with none.
     *
     * @param  list<string>  $inResponseTo
     * @param  ?string  $requestId
     * @param  bool  $unsolicited
     * @return void
     */
    #[DataProvider('provideEnvelopes')]
    public function testAnEnvelopeNamesOneRequestOnlyWhenEveryInResponseToAgrees(array $inResponseTo, ?string $requestId, bool $unsolicited): void
    {
        $envelope = new Envelope($inResponseTo, false);

        self::assertSame(
            [$requestId, $unsolicited, $inResponseTo, false],
            [$envelope->requestId(), $envelope->isUnsolicited(), $envelope->inResponseTo(), $envelope->isEncrypted()],
        );
        self::assertTrue((new Envelope($inResponseTo, true))->isEncrypted());
    }

    /**
     * A read result is read with its response, or refused with its reason and
     * detail.
     *
     * @return void
     */
    public function testAReadResultIsReadOrRefused(): void
    {
        $response = new SamlResponse(ValidationProfile::SOLICITED, '_r', CarbonImmutable::now(), new SamlStatus(SamlStatus::SUCCESS));
        $read     = ReadResult::read($response);
        $refused  = ReadResult::refused(FailureReason::RESPONSE_INVALID, 'schema');

        self::assertSame([true, $response, null, null], [$read->isRead(), $read->response, $read->reason, $read->detail]);
        self::assertSame([false, null, FailureReason::RESPONSE_INVALID, 'schema'], [$refused->isRead(), $refused->response, $refused->reason, $refused->detail]);
    }

    /**
     * A response policy asks for its keys only when called, has none unless
     * given, shows only counts, and refuses to be serialised.
     *
     * @return void
     */
    public function testAResponsePolicyYieldsItsKeysOnlyWhenAsked(): void
    {
        $asked  = new \ArrayObject;
        $policy = new ResponsePolicy(['cert'], ['a', 'b'], ['c'], ['d', 'e', 'f'], static function () use ($asked): array {
            $asked->append(true);

            return [new Secret('private-key-material')];
        });

        self::assertCount(0, $asked);
        self::assertSame(['trusted_certificates' => 1, 'signature_algorithms' => 2, 'key_transport_algorithms' => 1, 'data_encryption_algorithms' => 3], $policy->__debugInfo());
        self::assertSame('private-key-material', $policy->decryptionKeys()[0]->reveal());
        self::assertCount(1, $asked);
        self::assertSame([], (new ResponsePolicy([], []))->decryptionKeys());
        self::assertStringNotContainsString('private-key-material', print_r($policy, true));

        $this->expectExceptionObject(new \LogicException('A response policy cannot be serialised.'));

        serialize($policy);
    }

    /**
     * A response policy refuses to be unserialised.
     *
     * @return void
     */
    public function testAResponsePolicyRefusesToBeUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A response policy cannot be unserialised.'));

        (new ResponsePolicy([], []))->__unserialize([]);
    }
}
