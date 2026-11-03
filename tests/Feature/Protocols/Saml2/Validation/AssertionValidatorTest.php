<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Secrets\CountingSecretEncrypter;
use Tests\TestCase;

/**
 * Feature tests for the one core that validates a SAML response (SSO-6.2 to
 * SSO-6.11), with responses from the fake identity provider: the claims and
 * replay record of a solicited response and of the unsolicited profile; the
 * profile against whether a request was consumed; an unsuccessful response's
 * envelope, request and logged, sanitised status; a missing response and a
 * refused read, logged by its rule; each rule set answering in order; the
 * attributes of every attribute statement; the clock, skew and maximum age read
 * afresh; and decryption keys decrypted only for an encrypted assertion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssertionValidator::class)]
final class AssertionValidatorTest extends TestCase
{
    use CapturesLogs, UsesConnections;

    /** @var string The request the responses answer. */
    private const string REQUEST_ID = '_request-1';

    /** @var string The request's public reference. */
    private const string REFERENCE = 'Vq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /** @var string The persistent NameID format. */
    private const string PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /** @var string A status other than success. */
    private const string RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';

    /** @var string A second-level status. */
    private const string AUTHN_FAILED = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Secrets\CountingSecretEncrypter The encrypter, counting decryptions. */
    private CountingSecretEncrypter $encrypter;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the responses arrive for. */
    private Connection $connection;

    /**
     * Bind a fixed clock and a counting encrypter, configure the endpoints,
     * capture the logs, and create the tables and a connection that trusts the
     * identity provider and has an encryption key.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->encrypter = new CountingSecretEncrypter(app(SecretEncrypter::class));

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(SecretEncrypter::class, $this->encrypter);

        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->captureLogs();
        $this->createConnectionTables();

        $this->connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
        ]);

        $this->key(KeyUse::IDP_SIGNING, null, self::idp()->certificate(), null);
        $this->key(KeyUse::SP_ENCRYPTION, KeyState::CURRENT, self::spKeys()[1], self::spKeys()[0]);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A solicited response is verified with the identity provider as issuer,
     * the encoded subject and its format, the attributes, the authentication
     * context and no linking email, and the replay record of its assertion
     * until its earliest bound; nothing is logged or decrypted.
     *
     * @return void
     */
    public function testVerifiesASolicitedResponse(): void
    {
        $response   = $this->response()->with(['assertion_id' => '_assertion-7', 'not_on_or_after' => $this->now()->addMinutes(2)]);
        $completion = $this->validate($response, $this->consumed());
        $claims     = $completion->claims;

        self::assertNotNull($claims);
        self::assertSame(
            [FakeSamlIdentityProvider::ENTITY_ID, 'v1|7:name_id|52:' . self::PERSISTENT . '|-|-|5:alice', self::PERSISTENT, ['email' => ['alice@example.test']], null],
            [$claims->issuer, $claims->subject, $claims->nameIdFormat, $claims->attributes, $claims->linkingEmail],
        );
        self::assertSame([
            'authenticated_at'          => '2026-11-01T09:29:00.000000Z',
            'methods'                   => [],
            'context_class'             => FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT,
            'provider_session_id'       => '_session-1',
            'provider_session_deadline' => '2026-11-01T17:30:00.000000Z',
        ], $claims->authenticationContext->toArray());
        $this->assertReplayRecord($completion, '_assertion-7', '2026-11-01T09:33:00+00:00');
        self::assertSame([], $this->capturedLogRecords());
        self::assertSame(0, $this->encrypter->decryptions);
    }

    /**
     * With no consumed request, a response answering none is verified by the
     * unsolicited profile, with its replay record.
     *
     * @return void
     */
    public function testVerifiesAnUnsolicitedResponseWithNoRequest(): void
    {
        $response   = $this->response()->inResponseTo(null)->with(['assertion_id' => '_assertion-8']);
        $completion = $this->validate($response, null);

        self::assertSame('v1|7:name_id|52:' . self::PERSISTENT . '|-|-|5:alice', $completion->claims?->subject);
        $this->assertReplayRecord($completion, '_assertion-8', '2026-11-01T09:36:00+00:00');
    }

    /**
     * A solicited response with no consumed request, and an unsolicited one
     * with a consumed request, are each `request_unknown`: an `InResponseTo`
     * anywhere is never unsolicited.
     *
     * @return void
     */
    public function testTheProfileMustBeTheOneTheRequestCallsFor(): void
    {
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $this->validate($this->response(), null)->reason);
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $this->validate($this->response()->inResponseTo(null), $this->consumed())->reason);
    }

    /**
     * An unsuccessful response from the identity provider to the assertion
     * consumer service is `provider_error`, its status codes and its message,
     * sanitised, logged with the connection and the request's reference.
     *
     * @return void
     */
    public function testAnUnsuccessfulResponseIsAProviderErrorWithItsStatusLogged(): void
    {
        $response = $this->unsuccessful("Denied\r\nforged token=secret-value-1234");

        self::assertSame(FailureReason::PROVIDER_ERROR, $this->validate($response, $this->consumed())->reason);
        self::assertSame([[
            'channel' => 'sso_capture',
            'level'   => 'warning',
            'message' => 'sso.saml2.unsuccessful_status',
            'context' => [
                'connection_id'     => $this->connection->id,
                'request_reference' => self::REFERENCE,
                'status'            => self::RESPONDER,
                'sub_status'        => self::AUTHN_FAILED,
                'status_message'    => 'Denied forged token=[redacted]',
            ],
        ]], $this->capturedLogRecords());
        $this->assertNothingLoggedContains('secret-value-1234', "\n", "\r");
    }

    /**
     * An unsuccessful response without a message or a second-level status, by
     * the unsolicited profile, logs neither and names no request.
     *
     * @return void
     */
    public function testAnUnsuccessfulResponseToNoRequestLogsWhatItCarries(): void
    {
        $response = $this->unsuccessful(null)->inResponseTo(null)->with(['sub_status' => null]);

        self::assertSame(FailureReason::PROVIDER_ERROR, $this->validate($response, null)->reason);
        self::assertSame(
            ['connection_id' => $this->connection->id, 'request_reference' => null, 'status' => self::RESPONDER, 'sub_status' => null, 'status_message' => null],
            $this->capturedLogRecords()[0]['context'] ?? null,
        );
    }

    /**
     * Rows of `[changes, reason]`: an unsuccessful response's change, and the
     * refusal it answers before `provider_error`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideUnsuccessfulRefusals(): iterable
    {
        yield from [
            'another issuer'         => [['issuer' => 'https://attacker.example.test'], FailureReason::ISSUER_MISMATCH],
            'no issuer'              => [['issuer' => null], FailureReason::ISSUER_MISMATCH],
            'another destination'    => [['destination' => 'https://sp.example.test/other'], FailureReason::RECIPIENT_MISMATCH],
            'another request'        => [['in_response_to' => '_request-2'], FailureReason::REQUEST_MISMATCH],
            'no request'             => [['in_response_to' => null], FailureReason::REQUEST_MISMATCH],
            'another issuer and one' => [['issuer' => 'https://attacker.example.test', 'in_response_to' => '_request-2'], FailureReason::ISSUER_MISMATCH],
        ];
    }

    /**
     * An unsuccessful response from another issuer or naming none, to another
     * destination or for another request is refused for that, and nothing is
     * logged.
     *
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideUnsuccessfulRefusals')]
    public function testAnUnsuccessfulResponseIsHeldToItsEnvelope(array $changes, FailureReason $reason): void
    {
        self::assertSame($reason, $this->validate($this->unsuccessful('Denied')->with($changes), $this->consumed())->reason);
        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * A posted request with no response string is `response_invalid`, with
     * nothing read or logged.
     *
     * @return void
     */
    public function testAPostWithNoResponseIsInvalid(): void
    {
        foreach ([[], ['SAMLResponse' => ''], ['SAMLResponse' => ['x']], ['SAMLResponse' => 1]] as $body) {
            $completion = app(AssertionValidator::class)->validate($this->connection, $this->saml2Options(), new CompletionRequest('POST', '', $body), $this->consumed());

            self::assertSame(FailureReason::RESPONSE_INVALID, $completion->reason);
        }

        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * A response the adapter refuses is refused with its reason, and the rule
     * that refused it is logged, in the package's own words.
     *
     * @return void
     */
    public function testARefusedReadIsLoggedByItsRule(): void
    {
        $attacker = new FakeSamlIdentityProvider;

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->validate($this->response()->signedBy($attacker->signer()), $this->consumed())->reason);
        self::assertSame(FailureReason::RESPONSE_INVALID, $this->validate($this->response()->wrapped('xsw3'), null)->reason);
        self::assertSame([
            [
                'channel' => 'sso_capture',
                'level'   => 'notice',
                'message' => 'sso.saml2.response_refused',
                'context' => ['connection_id' => $this->connection->id, 'request_reference' => self::REFERENCE, 'reason' => 'signature_invalid', 'detail' => 'signature'],
            ],
            [
                'channel' => 'sso_capture',
                'level'   => 'notice',
                'message' => 'sso.saml2.response_refused',
                'context' => ['connection_id' => $this->connection->id, 'request_reference' => null, 'reason' => 'response_invalid', 'detail' => 'assertion_location'],
            ],
        ], $this->capturedLogRecords());
    }

    /**
     * Rows of `[changes, reason]`: a response breaking two rule sets, and the
     * refusal of the one that runs first.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideOrder(): iterable
    {
        $transient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
        $attacker  = 'https://attacker.example.test';
        $other     = [['https://other.example.test']];

        yield from [
            'the issuer before the audience'        => [['assertion_issuer' => $attacker, 'audiences' => $other], FailureReason::ISSUER_MISMATCH],
            'the audience before the confirmation'  => [['audiences' => $other, 'confirmations' => []], FailureReason::AUDIENCE_MISMATCH],
            'the confirmation before the subject'   => [['confirmations' => [], 'name_id_format' => $transient], FailureReason::RECIPIENT_MISMATCH],
            'the subject before the authentication' => [['name_id_format' => $transient, 'authn_statements' => []], FailureReason::SUBJECT_INVALID],
            'the authentication alone'              => [['authn_statements' => []], FailureReason::RESPONSE_INVALID],
        ];
    }

    /**
     * The rule sets run in order: the response's, the conditions', the
     * confirmations', the subject's, then the authentication's.
     *
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideOrder')]
    public function testRunsTheRuleSetsInOrder(array $changes, FailureReason $reason): void
    {
        self::assertSame($reason, $this->validate($this->response()->with($changes), $this->consumed())->reason);
    }

    /**
     * The attributes are those of every attribute statement, by name, each the
     * list of its string values in order: an attribute named twice holds both
     * lists' values, and a value that is not text is left out.
     *
     * @return void
     */
    public function testCarriesEveryAttributesStringValues(): void
    {
        $this->connection->forceFill(['settings' => [...$this->connection->settings, 'want_assertions_signed' => false]])->save();

        $xml = $this->response()->signed(false, false)->with(['attributes' => ['groups' => ['staff'], 'email' => ['alice@example.test']]])->toXml();
        $xml = str_replace('</saml:AttributeStatement>', '<saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>'
            . '<saml:Attribute Name="groups"><saml:AttributeValue xsi:nil="true"/></saml:Attribute></saml:AttributeStatement>', $xml);

        $completion = app(AssertionValidator::class)->validate($this->connection, $this->saml2Options(), self::posted(self::signed($xml)), $this->consumed());

        self::assertSame(['groups' => ['staff', 'admins'], 'email' => ['alice@example.test']], $completion->claims?->attributes);
    }

    /**
     * The time rules read the clock's now once the response is read, the skew
     * from `sso.clock.skew_seconds` and the maximum age from
     * `sso.saml2.issue_instant_max_age_seconds`, afresh on each call.
     *
     * @return void
     */
    public function testReadsTheClockTheSkewAndTheMaximumAgeAfresh(): void
    {
        $response = $this->response()->with(['not_on_or_after' => $this->now()->addMinutes(10), 'confirmations' => [$this->bearer($this->now()->addMinutes(10))]]);

        $this->clock->advance(330);

        self::assertTrue($this->validate($response, $this->consumed())->isVerified());

        config()->set('sso.saml2.issue_instant_max_age_seconds', 269);

        self::assertSame(FailureReason::ASSERTION_EXPIRED, $this->validate($response, $this->consumed())->reason);

        config()->set('sso.saml2.issue_instant_max_age_seconds', 300);
        config()->set('sso.clock.skew_seconds', 29);

        self::assertSame(FailureReason::ASSERTION_EXPIRED, $this->validate($response, $this->consumed())->reason);

        config()->set('sso.clock.skew_seconds', 30);

        self::assertTrue($this->validate($response, $this->consumed())->isVerified());
    }

    /**
     * The service provider's decryption key is decrypted for an encrypted
     * assertion, which is verified as a plain one, and never for a plain one.
     *
     * @return void
     */
    public function testDecryptsAKeyOnlyForAnEncryptedAssertion(): void
    {
        self::assertTrue($this->validate($this->response(), $this->consumed())->isVerified());
        self::assertSame(0, $this->encrypter->decryptions);

        self::assertTrue($this->validate($this->response()->encryptedFor(self::spKeys()[1]), $this->consumed())->isVerified());
        self::assertSame(1, $this->encrypter->decryptions);
    }

    /**
     * Assert the completion is verified with the replay record of the
     * assertion, scoped by the connection and the issuer, until the instant.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Completion  $completion
     * @param  string  $assertionId
     * @param  string  $until
     * @return void
     */
    private function assertReplayRecord(Completion $completion, string $assertionId, string $until): void
    {
        $replay = $completion->replay;

        self::assertNotNull($replay);
        self::assertSame(
            [ReplayRecord::SAML_ASSERTION, ReplayRecord::samlAssertion($this->connection->id, FakeSamlIdentityProvider::ENTITY_ID, $assertionId, $replay->until)->key(), $until],
            [$replay->namespace, $replay->key(), $replay->until->toIso8601String()],
        );
    }

    /**
     * Validate the response, posted, for the connection, against the request.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function validate(FakeSamlResponse $response, ?ConsumedRequest $consumed): Completion
    {
        return app(AssertionValidator::class)->validate($this->connection, $this->saml2Options(), $response->completionRequest('relay'), $consumed);
    }

    /**
     * A valid response from the trusted identity provider, made now, for the
     * connection's service provider and answering the request, with a fixed
     * session index.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);
        $response  = self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->now());
        $statement = [
            'instant'                 => $this->now()->subMinute(),
            'session_index'           => '_session-1',
            'session_not_on_or_after' => $this->now()->addHours(8),
            'class'                   => FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT,
        ];

        return $response->with(['authn_statements' => [$statement]])->inResponseTo(self::REQUEST_ID);
    }

    /**
     * An unsuccessful response answering the request, with no assertion, the
     * responder status, a second-level status and the message.
     *
     * @param  ?string  $message
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function unsuccessful(?string $message): FakeSamlResponse
    {
        return $this->response()->with(['status' => self::RESPONDER, 'sub_status' => self::AUTHN_FAILED, 'status_message' => $message, 'assertion' => false]);
    }

    /**
     * A bearer confirmation to the assertion consumer service for the request,
     * valid until the instant.
     *
     * @param  \Carbon\CarbonImmutable  $notOnOrAfter
     * @return array<string, mixed>
     */
    private function bearer(CarbonImmutable $notOnOrAfter): array
    {
        return [
            'method'          => FakeSamlResponse::BEARER,
            'data'            => true,
            'recipient'       => app(EndpointResolver::class)->endpoints($this->connection)->assertionConsumerService,
            'not_before'      => null,
            'not_on_or_after' => $notOnOrAfter,
            'in_response_to'  => self::REQUEST_ID,
        ];
    }

    /**
     * The request consumed for the responses.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     */
    private function consumed(): ConsumedRequest
    {
        return new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(self::REFERENCE), $this->now()->subMinute(), samlRequestId: self::REQUEST_ID);
    }

    /**
     * The connection's options, read now.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options
     */
    private function saml2Options(): Saml2Options
    {
        return Saml2Options::of($this->connection);
    }

    /**
     * The XML with the identity provider's signature over its root, posted.
     *
     * @param  string  $xml
     * @return string
     *
     * @throws \LogicException
     */
    private static function signed(string $xml): string
    {
        $document = new \DOMDocument;

        $document->loadXML($xml);
        self::idp()->signer()->sign($document->documentElement ?? throw new \LogicException('The response has a root.'));

        try {
            return base64_encode((string) $document->saveXML($document->documentElement));
        } catch (\DOMException $exception) {
            throw new \LogicException('The signed document could not be written.', 0, $exception);
        }
    }

    /**
     * What arrives when the encoded response is posted.
     *
     * @param  string  $encoded
     * @return \SineMacula\Laravel\Sso\Protocols\CompletionRequest
     */
    private static function posted(string $encoded): CompletionRequest
    {
        return new CompletionRequest('POST', '', ['SAMLResponse' => $encoded, 'RelayState' => 'relay']);
    }

    /**
     * Store a key or certificate of the use for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  string  $certificate
     * @param  ?string  $privateKey
     * @return void
     *
     * @throws \LogicException
     */
    private function key(KeyUse $use, ?KeyState $state, string $certificate, ?string $privateKey): void
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($certificate) ?: throw new \LogicException('A certificate has a public key.'));

        (new ConnectionKey)->forceFill([
            'connection_id'   => $this->connection->id,
            'use'             => $use,
            'state'           => $state,
            'key_type'        => KeyType::RSA,
            'key_bits'        => 2048,
            'certificate'     => $certificate,
            'public_key'      => is_array($details) ? $details['key'] : '',
            'private_key'     => $privateKey === null ? null : $this->encrypter->encrypt($privateKey),
            'fingerprint'     => (string) openssl_x509_fingerprint($certificate, 'sha256'),
            'made_current_at' => $state === null ? null : $this->now(),
        ])->save();
    }

    /**
     * The clock's now.
     *
     * @return \Carbon\CarbonImmutable
     */
    private function now(): CarbonImmutable
    {
        return $this->clock->now();
    }

    /**
     * The trusted identity provider, made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }

    /**
     * The service provider's encryption key and certificate, made once for the
     * class.
     *
     * @return array{0: string, 1: string}
     */
    private static function spKeys(): array
    {
        return self::$spKeys ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }
}
