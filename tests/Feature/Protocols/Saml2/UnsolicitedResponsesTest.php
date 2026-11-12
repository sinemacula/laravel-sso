<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\Reinitiation;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\UnsolicitedResponses;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for re-initiation from an unsolicited SAML response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnsolicitedResponses::class)]
final class UnsolicitedResponsesTest extends TestCase
{
    use CapturesLogs, UsesConnections;

    /** @var string The application start URL the connection sends the browser to. */
    private const string START_URL = 'https://app.example.com/sso/start';

    /** @var string The id of the assertion the valid response carries. */
    private const string ASSERTION_ID = '_assertion-unsolicited-1';

    /** @var string The transient NameID format, never a subject. */
    private const string TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider An identity provider the connection never trusts, made once. */
    private static ?FakeSamlIdentityProvider $attacker = null;

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the responses arrive for. */
    private Connection $connection;

    /**
     * Create a connection that allows IdP-initiated sign-in, trusts the
     * provider and has an encryption key.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.idp_initiated', true);
        config()->set('sso.endpoints.base_url', 'https://sp.example.test');

        $this->captureLogs();
        $this->usePackageTables();

        $this->connection = $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => [
                'idp_entity_id'           => FakeSamlIdentityProvider::ENTITY_ID,
                'sso_url'                 => FakeSamlIdentityProvider::SSO_URL,
                'idp_initiated'           => true,
                'idp_initiated_start_url' => self::START_URL,
            ],
        ]);

        $this->key(KeyUse::IDP_SIGNING, null, self::idp()->certificate(), null);
        $this->key(KeyUse::SP_ENCRYPTION, KeyState::CURRENT, self::spKeys()[1], self::spKeys()[0]);
    }

    /**
     * A connection that does not allow IdP-initiated sign-in refuses before
     * reading anything, logging only the connection.
     *
     * @return void
     */
    public function testAConnectionThatDoesNotAllowItRefusesBeforeReadingAnything(): void
    {
        $this->settings(['idp_initiated' => false]);

        foreach ([$this->response()->completionRequest(), new CompletionRequest('POST', '', [])] as $request) {

            $reinitiation = $this->reinitiate($request);

            self::assertSame([false, null, null, FailureReason::UNSOLICITED_NOT_ALLOWED], self::summary($reinitiation));
        }

        self::assertNull(app(UnsolicitedResponses::class)->startUrl($this->connection, Saml2Options::of($this->connection)));

        $record = [
            'channel' => 'sso_capture',
            'level'   => 'notice',
            'message' => 'sso.saml2.unsolicited_not_allowed',
            'context' => ['connection_id' => $this->connection->id],
        ];

        self::assertSame([$record, $record], $this->capturedLogRecords());
    }

    /**
     * A connection allowing IdP-initiated sign-in without a start URL fails
     * closed, logging nothing.
     *
     * @return void
     */
    public function testAnOptedInConnectionWithoutAStartUrlFailsClosed(): void
    {
        $this->settings(['idp_initiated' => true, 'idp_initiated_start_url' => null]);

        $options = Saml2Options::of($this->connection);

        self::assertTrue($options->isOn(Saml2Setting::IDP_INITIATED));
        self::assertNull($options->idpInitiatedStartUrl);

        $reinitiation = app(UnsolicitedResponses::class)->reinitiate($this->connection, $options, $this->response()->completionRequest());

        self::assertSame([false, null, null, FailureReason::CONNECTION_UNAVAILABLE], self::summary($reinitiation));
        self::assertNull(app(UnsolicitedResponses::class)->startUrl($this->connection, $options));
        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * Rows of `[start URL, expected]`: the start URL set, and the URL the
     * browser is sent to, with `{id}` the connection's id.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideStartUrls(): iterable
    {
        yield 'no query' => [self::START_URL, self::START_URL . '?connection={id}'];
        yield 'a query of its own' => [self::START_URL . '?tenant=acme', self::START_URL . '?tenant=acme&connection={id}'];
        yield 'an empty query' => [self::START_URL . '?', self::START_URL . '?connection={id}'];
        yield 'a query ending in a separator' => [self::START_URL . '?tenant=acme&', self::START_URL . '?tenant=acme&connection={id}'];
    }

    /**
     * A valid unsolicited response gets the start URL naming the connection and
     * its assertion's replay record.
     *
     * @param  string  $startUrl
     * @param  string  $expected
     * @return void
     */
    #[DataProvider('provideStartUrls')]
    public function testAValidResponseIsAllowedWithTheStartUrlNamingTheConnection(string $startUrl, string $expected): void
    {
        $this->settings(['idp_initiated_start_url' => $startUrl]);

        $reinitiation = $this->reinitiate($this->response()->completionRequest());
        $replay       = $reinitiation->replay;
        $key          = ReplayRecord::samlAssertion($this->connection->id, FakeSamlIdentityProvider::ENTITY_ID, self::ASSERTION_ID, $this->clock->now())->key();

        self::assertSame([true, str_replace('{id}', $this->connection->id, $expected), null], [$reinitiation->isAllowed(), $reinitiation->startUrl, $reinitiation->reason]);
        self::assertSame($reinitiation->startUrl, app(UnsolicitedResponses::class)->startUrl($this->connection, Saml2Options::of($this->connection)));
        self::assertSame(
            [ReplayRecord::SAML_ASSERTION, $key, '2026-11-01T09:36:00+00:00'],
            [$replay?->namespace, $replay?->key(), $replay?->until->toIso8601String()],
        );
        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * An encrypted unsolicited assertion is allowed once decrypted, by the same
     * rules.
     *
     * @return void
     */
    public function testAnEncryptedUnsolicitedAssertionIsAllowed(): void
    {
        $reinitiation = $this->reinitiate($this->response()->encryptedFor(self::spKeys()[1])->completionRequest());

        self::assertSame([true, self::START_URL . '?connection=' . $this->connection->id, null], [$reinitiation->isAllowed(), $reinitiation->startUrl, $reinitiation->reason]);
    }

    /**
     * A `RelayState` naming a URL is never read: the browser goes to the start
     * URL alone.
     *
     * @return void
     */
    public function testTheRelayStateIsNeverTheTarget(): void
    {
        foreach (['https://attacker.example.test/steal', '/relative/path', self::START_URL . '?connection=other'] as $relayState) {

            $reinitiation = $this->reinitiate($this->response()->completionRequest($relayState));

            self::assertSame(self::START_URL . '?connection=' . $this->connection->id, $reinitiation->startUrl);
        }
    }

    /**
     * Rows of `[change, reason]`: a valid unsolicited response changed, and the
     * reason it is refused for.
     *
     * @return iterable<string, array{
     *     0: \Closure(\SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse): \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse,
     *     1: \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     * }>
     */
    public static function provideRefusals(): iterable
    {
        yield 'another audience' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['audiences' => [['https://other.example.test/saml']]]),
            FailureReason::AUDIENCE_MISMATCH,
        ];
        yield 'expired conditions' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with([
                'not_before'      => CarbonImmutable::parse('2026-11-01T09:20:00Z'),
                'not_on_or_after' => CarbonImmutable::parse('2026-11-01T09:25:00Z'),
            ]),
            FailureReason::ASSERTION_EXPIRED,
        ];
        yield 'an unsigned assertion' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->signed(false, false),
            FailureReason::SIGNATURE_INVALID,
        ];
        yield 'an assertion signed by an attacker' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->signedBy(self::attacker()->signer()),
            FailureReason::SIGNATURE_INVALID,
        ];
        yield 'another issuer' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['issuer' => 'https://attacker.example.test/saml']),
            FailureReason::ISSUER_MISMATCH,
        ];
        yield 'another destination' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['destination' => 'https://sp.example.test/other']),
            FailureReason::RECIPIENT_MISMATCH,
        ];
        yield 'a transient NameID' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['name_id_format' => self::TRANSIENT]),
            FailureReason::SUBJECT_INVALID,
        ];
        yield 'an InResponseTo on the response' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['in_response_to' => '_request-elsewhere']),
            FailureReason::REQUEST_UNKNOWN,
        ];
        yield 'an InResponseTo on the confirmation only' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => self::confirmationOnly($response),
            FailureReason::REQUEST_UNKNOWN,
        ];
        yield 'an InResponseTo inside the encrypted assertion only' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => self::confirmationOnly($response)->encryptedFor(self::spKeys()[1]),
            FailureReason::REQUEST_UNKNOWN,
        ];
        yield 'an unsuccessful status' => [
            static fn (FakeSamlResponse $response): FakeSamlResponse => $response->with(['status' => 'urn:oasis:names:tc:SAML:2.0:status:Responder', 'assertion' => false]),
            FailureReason::PROVIDER_ERROR,
        ];
    }

    /**
     * Every rule of a successful response holds for an unsolicited one, and any
     * `InResponseTo` refuses it.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse): \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $change
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testEveryRuleOfASuccessfulResponseHolds(\Closure $change, FailureReason $reason): void
    {
        $reinitiation = $this->reinitiate($change($this->response())->completionRequest());

        self::assertSame([false, null, null, $reason], self::summary($reinitiation));
    }

    /**
     * A post with no response, or one the adapter cannot read, keeps the
     * validator's `response_invalid`.
     *
     * @return void
     */
    public function testAMissingOrUnreadableResponseIsInvalid(): void
    {
        foreach ([[], ['SAMLResponse' => ''], ['SAMLResponse' => base64_encode('<not-saml/>')]] as $body) {
            self::assertSame([false, null, null, FailureReason::RESPONSE_INVALID], self::summary($this->reinitiate(new CompletionRequest('POST', '', $body))));
        }
    }

    /**
     * The response with its bearer confirmation alone naming a request, its own
     * `InResponseTo` left out.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private static function confirmationOnly(FakeSamlResponse $response): FakeSamlResponse
    {
        return $response->inResponseTo('_request-elsewhere')->with(['in_response_to' => null]);
    }

    /**
     * Whether the re-initiation is allowed, its start URL, its replay record
     * and its reason.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Reinitiation  $reinitiation
     * @return array{0: bool, 1: ?string, 2: ?\SineMacula\Laravel\Sso\Protocols\ReplayRecord, 3: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}
     */
    private static function summary(Reinitiation $reinitiation): array
    {
        return [$reinitiation->isAllowed(), $reinitiation->startUrl, $reinitiation->replay, $reinitiation->reason];
    }

    /**
     * Re-initiate the request for the connection, with the options it holds
     * now.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @return \SineMacula\Laravel\Sso\Protocols\Reinitiation
     */
    private function reinitiate(CompletionRequest $request): Reinitiation
    {
        return app(UnsolicitedResponses::class)->reinitiate($this->connection, Saml2Options::of($this->connection), $request);
    }

    /**
     * A valid unsolicited response from the trusted identity provider, made
     * now, for the connection's service provider.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private function response(): FakeSamlResponse
    {
        $endpoints = app(EndpointResolver::class)->endpoints($this->connection);

        return self::idp()->response($endpoints->entityId, $endpoints->assertionConsumerService, $this->clock->now())->with(['assertion_id' => self::ASSERTION_ID]);
    }

    /**
     * Change the connection's settings, a `null` removing one.
     *
     * @param  array<string, mixed>  $settings
     * @return void
     */
    private function settings(array $settings): void
    {
        $this->connection->forceFill(['settings' => array_filter([...$this->connection->settings, ...$settings], static fn (mixed $value): bool => $value !== null)])->save();
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
            'made_current_at' => $state === null ? null : $this->clock->now(),
        ])->save();
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
     * An identity provider of the same entity id the connection never trusts,
     * made once for the class.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function attacker(): FakeSamlIdentityProvider
    {
        return self::$attacker ??= new FakeSamlIdentityProvider;
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
