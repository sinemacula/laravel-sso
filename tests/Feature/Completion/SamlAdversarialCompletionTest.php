<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionResult;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\ResponseCorrelator;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\BearerConfirmations;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ConditionRules;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ResponseRules;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\SubjectRules;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use SineMacula\Laravel\Sso\Testing\Saml\SignatureWrapping;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Handoffs\RecordingHandoffIssuer;
use Tests\TestCase;

/**
 * The hostile SAML responses of the response validation's review focus (SSO-6.2
 * to SSO-6.10, SSO-5.3, SSO-5.8), each posted through the public completion
 * helper as the fake identity provider builds it: every signature wrapping
 * variant, duplicate ids and two assertions, an unsigned assertion in a signed
 * response, an attacker's key and an untrusted embedded certificate, audience,
 * recipient and destination bypasses, every time rule, `InResponseTo`
 * disagreeing with itself or with `RelayState` or naming no request, every
 * refused encryption, required encryption, every subject rule, every
 * authentication rule, an unknown condition and an unsuccessful status.
 *
 * Each refused case reports exactly one `FlowFailed` with its reason and no
 * `ResultVerified`, records no assertion, and makes no link or handoff. A
 * comment inside a signed `NameID` yields the whole value; the four refused
 * encryptions are indistinguishable in their results, events and logs; and an
 * unsuccessful status's message is never logged unsanitised or put in an event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-type HostileRow array{
 *     0: \Closure(self): \SineMacula\Laravel\Sso\Protocols\CompletionRequest,
 *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason,
 *     2?: array<string, mixed>
 * }
 */
#[CoversClass(CompletionService::class)]
#[CoversClass(ResponseCorrelator::class)]
#[CoversClass(AssertionValidator::class)]
#[CoversClass(ResponseRules::class)]
#[CoversClass(ConditionRules::class)]
#[CoversClass(BearerConfirmations::class)]
#[CoversClass(SubjectRules::class)]
final class SamlAdversarialCompletionTest extends TestCase
{
    use CapturesLogs, DumpsValues, RecordsEventSequences, UsesConnections, UsesFlowTables;

    /** @var string The `AuthnRequest` id the request was started with. */
    private const string REQUEST_ID = '_request-hostile-1';

    /** @var string The `RelayState` the request was started with. */
    private const string RELAY_STATE = 'the-relay-state-of-the-hostile-saml-request';

    /** @var string Another request's `AuthnRequest` id. */
    private const string OTHER_REQUEST_ID = '_request-hostile-2';

    /** @var string Another request's `RelayState`. */
    private const string OTHER_RELAY_STATE = 'the-relay-state-of-another-saml-request';

    /** @var string The SAML assertion namespace. */
    private const string NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** @var string AES-128-CBC. */
    private const string AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    /** @var string RSA-OAEP with MGF1. */
    private const string RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    /** @var string AES-128-GCM. */
    private const string AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider An attacker's identity provider, made once. */
    private static ?FakeSamlIdentityProvider $attacker = null;

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Handoffs\RecordingHandoffIssuer The handoff issuer. */
    private RecordingHandoffIssuer $issuer;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The SAML connection the responses arrive for. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\AuthorizationRequest The request the responses answer. */
    private AuthorizationRequest $request;

    /**
     * Bind a fixed clock, the recording issuer and a request from an IP
     * address, configure SAML, the endpoints and the application, create the
     * tables, a connection that trusts the identity provider and has an
     * encryption key, and the request; capture logs and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock  = new FixedClock('2026-11-01T09:30:00Z');
        $this->issuer = new RecordingHandoffIssuer;

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(HandoffIssuer::class, $this->issuer);
        $this->app?->instance('request', Request::create('/auth/sso/connections/x/assertions', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.encrypted_assertions', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');
        config()->set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true, 'unlinked_handoffs' => true]]);

        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol'          => 'saml2',
            'enabled'           => true,
            'settings'          => ['idp_entity_id' => FakeSamlIdentityProvider::ENTITY_ID, 'sso_url' => FakeSamlIdentityProvider::SSO_URL],
            'attribute_mapping' => ['email' => 'email'],
        ]);

        $this->key(KeyUse::IDP_SIGNING, null, self::idp()->certificate(), null);
        $this->key(KeyUse::SP_ENCRYPTION, KeyState::CURRENT, self::spKeys()[1], self::spKeys()[0]);

        $this->request = $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => self::REQUEST_ID, 'state_digest' => hash('sha256', self::RELAY_STATE)]);

        $this->captureLogs();
        $this->startRecordingEvents();
    }

    /**
     * Rows of `[post, reason, settings]`: what the browser posts, built for the
     * test, the reason it is refused with, and the connection's settings
     * changed first.
     *
     * @return iterable<string, HostileRow>
     */
    public static function provideHostileResponses(): iterable
    {
        yield from self::wrappingResponses();
        yield from self::signatureResponses();
        yield from self::bindingResponses();
        yield from self::timeResponses();
        yield from self::correlationResponses();
        yield from self::subjectResponses();
        yield from self::authenticationResponses();
    }

    /**
     * Every hostile response is refused with its reason: exactly one
     * `FlowFailed` for the assertion flow, no `ResultVerified`, no assertion
     * recorded, and no link or handoff.
     *
     * @param  \Closure(self): \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $post
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  array<string, mixed>  $settings
     * @return void
     */
    #[DataProvider('provideHostileResponses')]
    public function testEveryHostileResponseIsRefused(\Closure $post, FailureReason $reason, array $settings = []): void
    {
        $this->settings($settings);

        $result = $this->complete($post($this));

        self::assertSame($reason, $result->reason);
        $this->assertRefusedCleanly($reason);
    }

    /**
     * A comment inside a `NameID` cannot truncate it: whether the response or
     * the assertion is signed over it, the subject is the whole value.
     *
     * @return void
     */
    public function testACommentInsideTheNameIdNeverTruncatesTheSubject(): void
    {
        $this->settings(['want_assertions_signed' => false]);

        self::assertTrue($this->complete($this->posted(self::commented($this->response(), 'response')))->isCompleted());

        $this->settings(['want_assertions_signed' => true]);
        $this->request = $this->otherRequestRow();

        $response = $this->response()->inResponseTo(self::OTHER_REQUEST_ID)->with(['assertion_id' => '_assertion-commented']);

        self::assertTrue($this->complete($this->posted(self::commented($response, 'assertion'), self::OTHER_RELAY_STATE))->isCompleted());

        $subject = 'v1|7:name_id|52:' . FakeSamlResponse::PERSISTENT . '|-|-|10:alice@evil';

        self::assertSame([$subject, $subject], array_map(static fn ($grant): string => $grant->result->subject, $this->issuer->grants()));
    }

    /**
     * With the assertion's own signature not wanted, an unsigned assertion
     * passes only through the response's signature: signed, it completes;
     * unsigned, it is refused.
     *
     * @return void
     */
    public function testAnUnsignedAssertionPassesOnlyThroughTheResponsesSignature(): void
    {
        $this->settings(['want_assertions_signed' => false]);

        self::assertSame(FailureReason::SIGNATURE_INVALID, $this->complete($this->posted($this->response()->signed(false, false)))->reason);
        $this->assertRefusedCleanly(FailureReason::SIGNATURE_INVALID);

        $this->request = $this->otherRequestRow();

        self::assertTrue($this->complete($this->posted($this->response()->inResponseTo(self::OTHER_REQUEST_ID)->signed(true, false), self::OTHER_RELAY_STATE))->isCompleted());
    }

    /**
     * A response signed by an attacker over an unsigned assertion, at a
     * connection that would take an assertion covered by the response's
     * signature alone, is refused for the response's own signature, by the rule
     * that verifies it and no other.
     *
     * @return void
     */
    public function testAResponseSignedByAnAttackerIsRefusedForItsOwnSignature(): void
    {
        $this->settings(['want_assertions_signed' => false]);

        $result = $this->complete($this->posted($this->response()->signed(true, false)->signedBy(self::attacker()->signer())));
        $logs   = $this->capturedLogRecords();

        self::assertSame(FailureReason::SIGNATURE_INVALID, $result->reason);
        self::assertSame([
            'channel' => 'sso_capture',
            'level'   => 'notice',
            'message' => 'sso.saml2.response_refused',
            'context' => ['connection_id' => $this->connection->id, 'request_reference' => $this->request->reference, 'reason' => 'signature_invalid', 'detail' => 'signature'],
        ], end($logs));
        $this->assertRefusedCleanly(FailureReason::SIGNATURE_INVALID);
    }

    /**
     * A trusted certificate past its expiry still verifies what its key signs,
     * so a tenant whose identity provider let its certificate lapse still signs
     * in (SSO-2.6): the expiry is only reported.
     *
     * @return void
     */
    public function testATrustedCertificatePastItsExpiryStillSignsIn(): void
    {
        [$privateKey, $certificate] = self::expiredKeyPair();

        $notAfter = openssl_x509_parse($certificate)['validTo_time_t'] ?? null;

        self::assertIsInt($notAfter);

        $this->clock->advance($notAfter - $this->clock->now()->getTimestamp() + 86400);
        $this->key(KeyUse::IDP_SIGNING, null, $certificate, null);

        $this->request = $this->otherRequestRow();
        $endpoints     = app(EndpointResolver::class)->endpoints($this->connection);
        $lapsed        = new FakeSamlIdentityProvider(FakeSamlIdentityProvider::ENTITY_ID, $privateKey, $certificate);
        $response      = $lapsed->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->now(0))
            ->with(['authn_statements' => [$this->statement()]])
            ->inResponseTo(self::OTHER_REQUEST_ID);

        self::assertLessThan($this->clock->now()->getTimestamp(), $notAfter);
        self::assertTrue($this->complete($this->posted($response, self::OTHER_RELAY_STATE))->isCompleted());
        self::assertCount(1, $this->issuer->grants());
    }

    /**
     * RSA 1.5 key transport, AES-CBC without a response signature, AES-256-GCM
     * and a tampered ciphertext are each `decryption_failed`, with the same
     * result, event and log but for the request each answers.
     *
     * @return void
     */
    public function testEveryRefusedDecryptionIsIndistinguishable(): void
    {
        $this->settings(['encryption_algorithms' => [self::RSA_OAEP_MGF1P, self::AES128_GCM, self::AES128_CBC]]);

        $certificate = self::spKeys()[1];
        $variants    = [
            'rsa 1.5'     => static fn (FakeSamlResponse $response): string => $response->encryptedFor($certificate, 'rsa-1_5', 'aes128-gcm')->encoded(),
            'cbc'         => static fn (FakeSamlResponse $response): string => $response->encryptedFor($certificate, 'rsa-oaep-mgf1p', 'aes128-cbc')->encoded(),
            'aes-256-gcm' => static fn (FakeSamlResponse $response): string => $response->encryptedFor($certificate, 'rsa-oaep-mgf1p', 'aes256-gcm')->encoded(),
            'tampered'    => static fn (FakeSamlResponse $response): string => base64_encode(self::tampered($response->encryptedFor($certificate)->toXml())),
        ];

        $seen = [];

        foreach ($variants as $name => $encode) {

            $requestId = '_request-decryption-' . count($seen);
            $relay     = 'the-relay-state-of-decryption-request-' . count($seen);
            $request   = $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => $requestId, 'state_digest' => hash('sha256', $relay)]);

            $this->startRecordingEvents();

            $result   = $this->complete(new CompletionRequest('POST', '', ['SAMLResponse' => $encode($this->response()->inResponseTo($requestId)), 'RelayState' => $relay]));
            $failures = array_map(
                static fn ($event): array => [$event::class, $event instanceof FlowFailed ? $event->reason : null, $event->context()->requestReference],
                $this->recordedEvents(),
            );
            $logs = array_map(static fn (array $record): array => [...$record, 'context' => [...$record['context'], 'request_reference' => '-']], $this->capturedLogRecords());

            self::assertSame([[FlowFailed::class, FailureReason::DECRYPTION_FAILED, $request->reference]], $failures, $name);

            $seen[$name] = [$result->status, $result->reason, $result->redirectUri, end($logs)];
        }

        self::assertCount(1, array_unique(array_map(serialize(...), $seen)));
        self::assertSame([
            'channel' => 'sso_capture',
            'level'   => 'notice',
            'message' => 'sso.saml2.response_refused',
            'context' => ['connection_id' => $this->connection->id, 'request_reference' => '-', 'reason' => 'decryption_failed', 'detail' => 'decryption'],
        ], $seen['tampered'][3]);
        self::assertSame(0, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
    }

    /**
     * A status other than success is `provider_error`: its status message is
     * logged only sanitised, and appears in no event and no event's dump.
     *
     * @return void
     */
    public function testAnUnsuccessfulStatusIsAProviderErrorWhoseMessageNeverLeaks(): void
    {
        $message  = "Denied\r\nforged-line token=secret-value-1234";
        $response = $this->response()->with([
            'status'         => 'urn:oasis:names:tc:SAML:2.0:status:Responder',
            'sub_status'     => 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
            'status_message' => $message,
            'assertion'      => false,
        ]);

        self::assertSame(FailureReason::PROVIDER_ERROR, $this->complete($this->posted($response))->reason);
        $this->assertRefusedCleanly(FailureReason::PROVIDER_ERROR);
        $this->assertLoggedContains('Denied forged-line token=[redacted]', 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed');
        $this->assertNothingLoggedContains($message, 'secret-value-1234', "\n", "\r");

        foreach (self::dumps($this->recordedEvents()) as $dump) {
            self::assertStringNotContainsString('Denied', $dump);
            self::assertStringNotContainsString('secret-value-1234', $dump);
        }
    }

    /**
     * The signature wrapping variants, duplicate ids and two assertions.
     *
     * @return iterable<string, HostileRow>
     */
    private static function wrappingResponses(): iterable
    {
        foreach (SignatureWrapping::VARIANTS as $variant) {
            yield 'signature wrapping ' . $variant => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()->wrapped($variant)),
                FailureReason::RESPONSE_INVALID,
            ];
        }

        yield from [
            'the response and the assertion sharing an id' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()->with(['response_id' => '_shared', 'assertion_id' => '_shared'])),
                FailureReason::RESPONSE_INVALID,
            ],
            'two signed assertions' => [
                static fn (self $test): CompletionRequest => $test->posted(base64_encode(self::twoAssertions($test->response()))),
                FailureReason::RESPONSE_INVALID,
            ],
        ];
    }

    /**
     * Unsigned, wrongly signed and wrongly keyed responses.
     *
     * @return iterable<string, HostileRow>
     */
    private static function signatureResponses(): iterable
    {
        yield from [
            'an unsigned assertion in a signed response' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()->signed(true, false)),
                FailureReason::SIGNATURE_INVALID,
            ],
            'an assertion signed by an attacker' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()->signedBy(self::attacker()->signer())),
                FailureReason::SIGNATURE_INVALID,
            ],
            'an attacker key presenting the trusted certificate' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()->signedBy(self::impostor()->signer())),
                FailureReason::SIGNATURE_INVALID,
            ],
            'a response signed by an attacker' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()->signed(true, false)->signedBy(self::attacker()->signer())),
                FailureReason::SIGNATURE_INVALID,
                ['want_assertions_signed' => false],
            ],
            'a plain assertion where encryption is required' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()),
                FailureReason::ENCRYPTION_REQUIRED,
                ['require_encrypted_assertions' => true],
            ],
        ];
    }

    /**
     * Issuer, audience, recipient and destination bypasses, and unknown
     * conditions.
     *
     * @return iterable<string, HostileRow>
     */
    private static function bindingResponses(): iterable
    {
        $attacker = 'https://attacker.example.test/saml';
        $other    = 'https://other.example.test/saml';

        yield from [
            'another assertion issuer' => [
                static fn (self $test): CompletionRequest => $test->changed(['assertion_issuer' => $attacker]),
                FailureReason::ISSUER_MISMATCH,
            ],
            'another response issuer' => [
                static fn (self $test): CompletionRequest => $test->changed(['issuer' => $attacker]),
                FailureReason::ISSUER_MISMATCH,
            ],
            'another audience' => [
                static fn (self $test): CompletionRequest => $test->changed(['audiences' => [[$other]]]),
                FailureReason::AUDIENCE_MISMATCH,
            ],
            'one of two audience restrictions without us' => [
                static fn (self $test): CompletionRequest => $test->changed(['audiences' => [[$test->entityId()], [$other]]]),
                FailureReason::AUDIENCE_MISMATCH,
            ],
            'a recipient elsewhere' => [
                static fn (self $test): CompletionRequest => $test->changed(['confirmations' => [$test->bearer(['recipient' => 'https://evil.example.test/acs'])]]),
                FailureReason::RECIPIENT_MISMATCH,
            ],
            'a destination elsewhere' => [
                static fn (self $test): CompletionRequest => $test->changed(['destination' => 'https://evil.example.test/acs']),
                FailureReason::RECIPIENT_MISMATCH,
            ],
            'a signed response without a destination' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()->signed(true, true)->with(['destination' => null])),
                FailureReason::RECIPIENT_MISMATCH,
            ],
            'an unsigned response without a destination' => [
                static fn (self $test): CompletionRequest => $test->changed(['destination' => null]),
                FailureReason::RECIPIENT_MISMATCH,
            ],
            'a condition of a type the package does not use' => [
                static fn (self $test): CompletionRequest => $test->posted(self::signedAssertion(self::withCondition($test->response()))),
                FailureReason::CONDITION_UNSUPPORTED,
            ],
            'a condition of a type no schema defines' => [
                static fn (self $test): CompletionRequest => $test->changed(['unknown_conditions' => 1]),
                FailureReason::RESPONSE_INVALID,
            ],
        ];
    }

    /**
     * Every time rule broken.
     *
     * @return iterable<string, HostileRow>
     */
    private static function timeResponses(): iterable
    {
        $rows = [
            'expired conditions'                => static fn (self $test): array => ['not_before' => $test->now(-120), 'not_on_or_after' => $test->now(-61)],
            'conditions not yet valid'          => static fn (self $test): array => ['not_before' => $test->now(61)],
            'a bearer without NotOnOrAfter'     => static fn (self $test): array => ['confirmations' => [$test->bearer(['not_on_or_after' => null])]],
            'an expired bearer'                 => static fn (self $test): array => ['confirmations' => [$test->bearer(['not_on_or_after' => $test->now(-61)])]],
            'a bearer with NotBefore'           => static fn (self $test): array => ['confirmations' => [$test->bearer(['not_before' => $test->now(-60)])]],
            'a response issued too long ago'    => static fn (self $test): array => ['issue_instant' => $test->now(-361)],
            'an assertion issued too long ago'  => static fn (self $test): array => ['assertion_issue_instant' => $test->now(-361)],
            'a response issued in the future'   => static fn (self $test): array => ['issue_instant' => $test->now(61)],
            'an assertion issued in the future' => static fn (self $test): array => ['assertion_issue_instant' => $test->now(61)],
        ];

        foreach ($rows as $name => $changes) {
            yield $name => [static fn (self $test): CompletionRequest => $test->changed($changes($test)), FailureReason::ASSERTION_EXPIRED];
        }
    }

    /**
     * `InResponseTo` disagreeing with itself or with `RelayState`, or naming no
     * request.
     *
     * @return iterable<string, HostileRow>
     */
    private static function correlationResponses(): iterable
    {
        yield from [
            'the response naming another request than its confirmation' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()->with(['in_response_to' => $test->otherRequest()])),
                FailureReason::REQUEST_UNKNOWN,
            ],
            'an encrypted confirmation naming another request than the response' => [
                static fn (self $test): CompletionRequest => $test->posted(
                    $test->response()->with(['in_response_to' => $test->otherRequest()])->encryptedFor(self::spKeys()[1]),
                    self::OTHER_RELAY_STATE,
                ),
                FailureReason::REQUEST_MISMATCH,
            ],
            'an encrypted assertion whose second bearer names another request' => [
                static fn (self $test): CompletionRequest => $test->posted(
                    $test->response()->with(['confirmations' => [$test->bearer([]), $test->bearer(['in_response_to' => $test->otherRequest()])]])->encryptedFor(self::spKeys()[1]),
                ),
                FailureReason::REQUEST_MISMATCH,
            ],
            'a plain assertion whose second bearer names another request' => [
                static fn (self $test): CompletionRequest => $test->changed([
                    'confirmations' => [$test->bearer([]), $test->bearer(['in_response_to' => $test->otherRequest()])],
                ]),
                FailureReason::REQUEST_UNKNOWN,
            ],
            'a RelayState of another request' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response(), $test->otherRelayState()),
                FailureReason::REQUEST_MISMATCH,
            ],
            'no RelayState' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response(), null),
                FailureReason::REQUEST_MISMATCH,
            ],
            'an unknown request, never unsolicited' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()->inResponseTo('_request-unknown')),
                FailureReason::REQUEST_UNKNOWN,
            ],
        ];
    }

    /**
     * Every subject rule broken.
     *
     * @return iterable<string, HostileRow>
     */
    private static function subjectResponses(): iterable
    {
        $email     = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
        $transient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
        $attribute = ['subject_source' => 'attribute', 'subject_attribute' => 'employeeNumber'];

        yield from [
            'a transient NameID' => [
                static fn (self $test): CompletionRequest => $test->changed(['name_id_format' => $transient]),
                FailureReason::SUBJECT_INVALID,
            ],
            'an email NameID not allowed' => [
                static fn (self $test): CompletionRequest => $test->changed(['name_id' => 'alice@example.test', 'name_id_format' => $email]),
                FailureReason::SUBJECT_INVALID,
            ],
            'another NameQualifier' => [
                static fn (self $test): CompletionRequest => $test->changed(['name_qualifier' => 'https://attacker.example.test/saml']),
                FailureReason::SUBJECT_INVALID,
            ],
            'another SPNameQualifier' => [
                static fn (self $test): CompletionRequest => $test->changed(['sp_name_qualifier' => 'https://other.example.test/saml']),
                FailureReason::SUBJECT_INVALID,
            ],
            'no NameID' => [
                static fn (self $test): CompletionRequest => $test->changed(['name_id' => null]),
                FailureReason::SUBJECT_INVALID,
            ],
            'an over-long subject' => [
                static fn (self $test): CompletionRequest => $test->changed(['attributes' => ['employeeNumber' => [str_repeat('e', 1000)]]]),
                FailureReason::SUBJECT_INVALID,
                $attribute,
            ],
            'a subject attribute with two values' => [
                static fn (self $test): CompletionRequest => $test->changed(['attributes' => ['employeeNumber' => ['E-1', 'E-2']]]),
                FailureReason::SUBJECT_INVALID,
                $attribute,
            ],
        ];
    }

    /**
     * Every authentication rule broken.
     *
     * @return iterable<string, HostileRow>
     */
    private static function authenticationResponses(): iterable
    {
        yield from [
            'two authentication statements' => [
                static fn (self $test): CompletionRequest => $test->changed(['authn_statements' => [$test->statement(), $test->statement()]]),
                FailureReason::RESPONSE_INVALID,
            ],
            'another context class' => [
                static fn (self $test): CompletionRequest => $test->posted($test->response()),
                FailureReason::AUTHENTICATION_CONTEXT_MISMATCH,
                ['requested_authn_context' => ['https://refeds.org/profile/mfa']],
            ],
            'an elapsed provider session' => [
                static fn (self $test): CompletionRequest => $test->changed(['authn_statements' => [$test->statement(['session_not_on_or_after' => $test->now(0)])]]),
                FailureReason::AUTHENTICATION_EXPIRED,
            ],
            'an authentication too old for the maximum age' => [
                static fn (self $test): CompletionRequest => $test->changed(['authn_statements' => [$test->statement(['instant' => $test->now(-121)])]]),
                FailureReason::AUTHENTICATION_EXPIRED,
                ['max_authentication_age_seconds' => 60],
            ],
            'an authentication in the future' => [
                static fn (self $test): CompletionRequest => $test->changed(['authn_statements' => [$test->statement(['instant' => $test->now(61)])]]),
                FailureReason::ASSERTION_EXPIRED,
            ],
            'a reauthentication with an old authentication' => [
                static fn (self $test): CompletionRequest => $test->reauthenticating()->changed(['authn_statements' => [$test->statement(['instant' => $test->now(-61)])]]),
                FailureReason::AUTHENTICATION_EXPIRED,
            ],
        ];
    }

    /**
     * Assert the completion reported exactly one `FlowFailed` for the reason
     * and the assertion flow and nothing else, recorded no assertion, and made
     * no link or handoff.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    private function assertRefusedCleanly(FailureReason $reason): void
    {
        $this->assertExactlyOneFailure(Flow::ASSERTION, $reason);
        $this->assertEventSequence([FlowFailed::class]);

        self::assertSame(0, SingleUseKey::query()->where('namespace', ReplayRecord::SAML_ASSERTION)->count());
        self::assertSame(0, Link::query()->count());
        self::assertSame([], $this->issuer->grants());
    }

    /**
     * Complete at the connection's assertion consumer service with what was
     * posted.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Completion\CompletionResult
     */
    private function complete(CompletionRequest $request): CompletionResult
    {
        return app(CompletionService::class)->complete(CompletionEndpoint::ASSERTION_CONSUMER_SERVICE, $this->connection->id, $request, Clients::browser());
    }

    /**
     * What the browser posts: the response, or an encoded one, with the
     * `RelayState`, none for `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse|string  $response
     * @param  ?string  $relayState
     * @return \SineMacula\Laravel\Sso\Protocols\CompletionRequest
     */
    private function posted(FakeSamlResponse|string $response, ?string $relayState = self::RELAY_STATE): CompletionRequest
    {
        $encoded = $response instanceof FakeSamlResponse ? $response->encoded() : $response;

        return new CompletionRequest('POST', '', array_filter(['SAMLResponse' => $encoded, 'RelayState' => $relayState], static fn (?string $value): bool => $value !== null));
    }

    /**
     * What the browser posts: a valid response with the changes given, and the
     * request's `RelayState`.
     *
     * @param  array<string, mixed>  $changes
     * @return \SineMacula\Laravel\Sso\Protocols\CompletionRequest
     */
    private function changed(array $changes): CompletionRequest
    {
        return $this->posted($this->response()->with($changes));
    }

    /**
     * A valid response from the trusted identity provider, made now, for the
     * connection's service provider, answering the request, with a fixed
     * authentication statement.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->now(0))
            ->with(['authn_statements' => [$this->statement()]])
            ->inResponseTo(self::REQUEST_ID);
    }

    /**
     * The default bearer confirmation with the changes given.
     *
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    private function bearer(array $changes): array
    {
        return [
            'method'          => FakeSamlResponse::BEARER,
            'data'            => true,
            'recipient'       => app(EndpointResolver::class)->endpoints($this->connection)->assertionConsumerService,
            'not_before'      => null,
            'not_on_or_after' => $this->now(300),
            'in_response_to'  => self::REQUEST_ID,
            ...$changes,
        ];
    }

    /**
     * The default authentication statement with the changes given: a minute
     * old, with a session index, an eight-hour deadline and the
     * password-protected-transport class.
     *
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    private function statement(array $changes = []): array
    {
        return [
            'instant'                 => $this->now(-60),
            'session_index'           => '_session-1',
            'session_not_on_or_after' => $this->now(28800),
            'class'                   => FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT,
            ...$changes,
        ];
    }

    /**
     * The connection's service provider entity id.
     *
     * @return string
     */
    private function entityId(): string
    {
        return app(EndpointResolver::class)->endpoints($this->connection)->entityId;
    }

    /**
     * Store another request of the connection and answer its `AuthnRequest` id.
     *
     * @return string
     */
    private function otherRequest(): string
    {
        $this->otherRequestRow();

        return self::OTHER_REQUEST_ID;
    }

    /**
     * Store another request of the connection, with its own `AuthnRequest` id
     * and `RelayState`.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private function otherRequestRow(): AuthorizationRequest
    {
        return $this->makeAuthorizationRequest($this->connection, ['saml_request_id' => self::OTHER_REQUEST_ID, 'state_digest' => hash('sha256', self::OTHER_RELAY_STATE)]);
    }

    /**
     * Store another request of the connection and answer its `RelayState`.
     *
     * @return string
     */
    private function otherRelayState(): string
    {
        $this->otherRequest();

        return self::OTHER_RELAY_STATE;
    }

    /**
     * Make the request a `reauthenticate` one for an identity's session,
     * started now.
     *
     * @return self
     */
    private function reauthenticating(): self
    {
        $this->request->forceFill(['purpose' => 'reauthenticate', 'identity_type' => 'App\Models\User', 'identity_id' => '42', 'session_id' => 'session-1'])->save();

        return $this;
    }

    /**
     * Change the connection's settings.
     *
     * @param  array<string, mixed>  $settings
     * @return void
     */
    private function settings(array $settings): void
    {
        $this->connection->forceFill(['settings' => [...$this->connection->settings, ...$settings]])->save();
    }

    /**
     * The clock's now, moved by the seconds.
     *
     * @param  int  $seconds
     * @return \Carbon\CarbonImmutable
     */
    private function now(int $seconds): CarbonImmutable
    {
        return $this->clock->now()->addSeconds($seconds);
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
            'private_key'     => $privateKey === null ? null : app(SecretEncrypter::class)->encrypt($privateKey),
            'fingerprint'     => (string) openssl_x509_fingerprint($certificate, 'sha256'),
            'made_current_at' => $state === null ? null : $this->now(0),
        ])->save();
    }

    /**
     * The response with `alice@evil` as its `NameID`, a comment splitting it,
     * signed over the comment in the response's envelope or in the assertion.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @param  string  $signed
     * @return string
     *
     * @throws \LogicException
     */
    private static function commented(FakeSamlResponse $response, string $signed): string
    {
        $xml      = str_replace('>alice@evil<', '>alice<!--x-->@evil<', $response->signed(false, false)->with(['name_id' => 'alice@evil'])->toXml());
        $document = self::load($xml);
        $element  = $signed === 'response' ? $document->documentElement : $document->getElementsByTagNameNS(self::NS_SAML, 'Assertion')->item(0);

        self::idp()->signer()->sign($element instanceof \DOMElement ? $element : throw new \LogicException('The response has the element.'));

        try {
            return base64_encode((string) $document->saveXML($document->documentElement));
        } catch (\DOMException $exception) {
            throw new \LogicException('The signed document could not be written.', 0, $exception);
        }
    }

    /**
     * The response with a second signed assertion, of another id, after its
     * own.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @return string
     */
    private static function twoAssertions(FakeSamlResponse $response): string
    {
        preg_match('#<saml:Assertion .*</saml:Assertion>#s', $response->with(['assertion_id' => '_second'])->toXml(), $second);

        return str_replace('</saml:Assertion>', '</saml:Assertion>' . ($second[0] ?? ''), $response->toXml());
    }

    /**
     * The response's XML, its assertion unsigned, with a `Condition` typed as
     * an audience restriction, which the schema accepts and the package does
     * not use as one.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @return string
     */
    private static function withCondition(FakeSamlResponse $response): string
    {
        $condition = '<saml:Condition xsi:type="saml:AudienceRestrictionType"><saml:Audience>https://other.example.test/saml</saml:Audience></saml:Condition>';

        return str_replace('</saml:Conditions>', $condition . '</saml:Conditions>', $response->signed(false, false)->toXml());
    }

    /**
     * The XML with its assertion signed by the identity provider, encoded.
     *
     * @param  string  $xml
     * @return string
     *
     * @throws \LogicException
     */
    private static function signedAssertion(string $xml): string
    {
        $document  = self::load($xml);
        $assertion = $document->getElementsByTagNameNS(self::NS_SAML, 'Assertion')->item(0);

        self::idp()->signer()->sign($assertion instanceof \DOMElement ? $assertion : throw new \LogicException('The response has an assertion.'));

        try {
            return base64_encode((string) $document->saveXML($document->documentElement));
        } catch (\DOMException $exception) {
            throw new \LogicException('The signed document could not be written.', 0, $exception);
        }
    }

    /**
     * The encrypted response's XML with one bit of its assertion's ciphertext
     * flipped.
     *
     * @param  string  $xml
     * @return string
     */
    private static function tampered(string $xml): string
    {
        $pattern = '#(<xenc:CipherValue>)([^<]+)(</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>)#';

        return (string) preg_replace_callback($pattern, static function (array $match): string {
            $bytes     = (string) base64_decode($match[2], true);
            $bytes[20] = chr(ord($bytes[20]) ^ 1);

            return $match[1] . base64_encode($bytes) . $match[3];
        }, $xml);
    }

    /**
     * The XML parsed.
     *
     * @param  string  $xml
     * @return \DOMDocument
     */
    private static function load(string $xml): \DOMDocument
    {
        $document = new \DOMDocument;

        $document->loadXML($xml);

        return $document;
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
     * An attacker's identity provider, with its own key and certificate, made
     * once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function attacker(): FakeSamlIdentityProvider
    {
        return self::$attacker ??= new FakeSamlIdentityProvider;
    }

    /**
     * An attacker signing with the attacker's key while presenting the trusted
     * identity provider's certificate.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function impostor(): FakeSamlIdentityProvider
    {
        [$key] = FakeSamlIdentityProvider::keyPair('impostor');

        return new FakeSamlIdentityProvider(FakeSamlIdentityProvider::ENTITY_ID, $key, self::idp()->certificate());
    }

    /**
     * A fresh RSA key pair of 2048 bits and a self-signed certificate whose
     * validity ends the moment it is made: the private key, then the
     * certificate, both PEM.
     *
     * @return array{0: string, 1: string}
     */
    private static function expiredKeyPair(): array
    {
        $key  = openssl_pkey_new(['private_key_bits' => 2048]);
        $csr  = $key === false ? false : openssl_csr_new(['commonName' => 'lapsed.example.test'], $key);
        $cert = $key === false || !$csr instanceof \OpenSSLCertificateSigningRequest ? false : openssl_csr_sign($csr, null, $key, 0, ['digest_alg' => 'sha256']);

        if ($key === false || $cert === false || !openssl_pkey_export($key, $private) || !openssl_x509_export($cert, $certificate)) {
            self::fail('An expired key pair could not be made.');
        }

        return [$private, $certificate];
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
