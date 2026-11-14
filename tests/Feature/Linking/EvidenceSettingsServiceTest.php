<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\EvidenceSettingsService;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\EvidenceRules;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\RecordsLockOrder;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Feature tests of the helper that sets a connection's evidence policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EvidenceSettingsService::class)]
#[CoversClass(EvidenceRules::class)]
final class EvidenceSettingsServiceTest extends LinkingTestCase
{
    use CapturesLogs, RecordsLockOrder;

    /** @var string A class a policy accepts, which nothing may show. */
    private const string CLASS_VALUE = 'urn:example:the-accepted-class';

    /** @var array<string, mixed> A whole policy. */
    private const array POLICY = [
        'amr'          => ['pwd', 'otp'],
        'acr'          => [self::CLASS_VALUE],
        'combinations' => [['amr' => ['pwd', 'otp']], ['amr' => ['pwd'], 'acr' => self::CLASS_VALUE]],
    ];

    /** @var array<string, mixed> A whole policy for a SAML connection. */
    private const array SAML_POLICY = [
        'authn_context_class_ref' => [self::CLASS_VALUE],
        'combinations'            => [['authn_context_class_ref' => self::CLASS_VALUE]],
    ];

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFreshness The freshness contract. */
    private FakeFreshness $freshness;

    /**
     * Bind a freshness contract that answers `fresh`, turn SAML on, and start
     * recording anew.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = FakeFreshness::fresh();

        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.saml2', true);

        $this->startRecordingEvents();
    }

    /**
     * A connection holds an empty policy by default; an unknown connection and
     * another tenant's have none to read.
     *
     * @return void
     */
    public function testAConnectionHoldsNothingByDefault(): void
    {
        self::assertSame([], self::service()->get('tenant-1', $this->connection->id));
        self::assertNull(self::service()->get('tenant-2', $this->connection->id));
        self::assertNull(self::service()->get('TENANT-1', $this->connection->id));
        self::assertNull(self::service()->get('tenant-1', '01jbexampleconnection00000'));
    }

    /**
     * A change writes the policy, names what changed in sorted order and
     * reports `ConnectionUpdated` once.
     *
     * @return void
     */
    public function testASetWritesAndReportsNamesAlone(): void
    {
        $before = Connection::query()->whereKey($this->connection->id)->sole();
        $result = self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser(), new Caller(new IdentityReference('App\Models\User', '42')));
        $after  = Connection::query()->whereKey($this->connection->id)->sole();
        $names  = ['evidence.acr', 'evidence.amr', 'evidence.combinations'];

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame($names, $result->changedSettings);
        self::assertSame($this->connection->id, $result->connection?->id);
        self::assertTrue(SettingRules::isSame(self::POLICY, $after->getEvidencePolicy()));
        self::assertTrue(SettingRules::isSame(self::POLICY, self::service()->get('tenant-1', $this->connection->id)));

        foreach (['trust_version', 'linking_version', 'links_version', 'flows_version'] as $version) {
            self::assertSame($before->getAttribute($version), $after->getAttribute($version), $version);
        }

        self::assertSame([FreshnessOperation::CONNECTION_TRUST], array_column($this->freshness->asked(), 'operation'));

        $this->assertEventSequence([ConnectionUpdated::class]);

        $event = $this->recordedEvents()[0] ?? null;

        self::assertInstanceOf(ConnectionUpdated::class, $event);
        self::assertSame($names, $event->changedSettings);
        self::assertSame($this->connection->id, $event->context->connectionId);
        self::assertSame('42', $event->context->actingIdentityId);
        self::assertStringNotContainsString(self::CLASS_VALUE, print_r($event, true));
        self::assertStringNotContainsString(self::CLASS_VALUE, (string) json_encode($event));
        self::assertStringNotContainsString(self::CLASS_VALUE, (string) json_encode($result));
    }

    /**
     * Only what changed is named, the policy being replaced whole.
     *
     * @return void
     */
    public function testOnlyWhatChangedIsNamed(): void
    {
        self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser());

        $this->startRecordingEvents();

        $amr = ['amr' => ['pwd', 'otp', 'hwk']] + self::POLICY;

        self::assertSame(['evidence.amr'], self::service()->set('tenant-1', $this->connection->id, $amr, Clients::browser())->changedSettings);

        $cut = ['amr' => ['pwd'], 'combinations' => [['amr' => ['pwd']]]];

        self::assertSame(
            ['evidence.acr', 'evidence.amr', 'evidence.combinations'],
            self::service()->set('tenant-1', $this->connection->id, $cut, Clients::browser())->changedSettings,
        );
        self::assertTrue(SettingRules::isSame($cut, self::service()->get('tenant-1', $this->connection->id)));
        self::assertCount(2, $this->recordedEvents());
    }

    /**
     * What changed is named wherever it comes among what did not.
     *
     * @return void
     */
    public function testWhatChangedIsNamedAfterWhatDidNot(): void
    {
        self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser());

        $changed = ['combinations' => [['amr' => ['pwd']]]] + self::POLICY;

        self::assertSame(['evidence.combinations'], self::service()->set('tenant-1', $this->connection->id, $changed, Clients::browser())->changedSettings);
    }

    /**
     * A policy the row holds is `unchanged`, whatever the key order of its
     * maps, and writes and reports nothing.
     *
     * @return void
     */
    public function testAChangeOfNothingIsUnchanged(): void
    {
        self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser());

        $this->startRecordingEvents();

        $reordered = [
            'combinations' => [['amr' => ['pwd', 'otp']], ['acr' => self::CLASS_VALUE, 'amr' => ['pwd']]],
            'acr'          => [self::CLASS_VALUE],
            'amr'          => ['pwd', 'otp'],
        ];

        foreach ([self::POLICY, $reordered] as $policy) {

            $result = self::service()->set('tenant-1', $this->connection->id, $policy, Clients::browser());

            self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
            self::assertSame([], $result->changedSettings);
            self::assertSame($this->connection->id, $result->connection?->id);
        }

        $this->assertEventSequence([]);
    }

    /**
     * An empty policy clears the column, and clearing what is clear changes
     * nothing.
     *
     * @return void
     */
    public function testAnEmptyPolicyClearsIt(): void
    {
        self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser());

        $result = self::service()->set('tenant-1', $this->connection->id, [], Clients::browser());

        self::assertSame(['evidence.acr', 'evidence.amr', 'evidence.combinations'], $result->changedSettings);
        self::assertNull(self::column($this->connection->id));
        self::assertSame([], self::service()->get('tenant-1', $this->connection->id));

        $this->startRecordingEvents();

        self::assertSame(ConnectionStatus::UNCHANGED, self::service()->set('tenant-1', $this->connection->id, [], Clients::browser())->status);

        $this->assertEventSequence([]);
    }

    /**
     * A row the package did not write reads as what it holds, or as nothing for
     * what is no policy at all, and can be replaced.
     *
     * @return void
     */
    public function testARowThePackageDidNotWriteCanBeReplaced(): void
    {
        self::writeColumn($this->connection->id, '{"other":true}');

        self::assertSame(['other' => true], self::service()->get('tenant-1', $this->connection->id));

        $cleared = self::service()->set('tenant-1', $this->connection->id, [], Clients::browser());

        self::assertSame(['evidence.other'], $cleared->changedSettings);
        self::assertNull(self::column($this->connection->id));

        self::writeColumn($this->connection->id, '5');

        self::assertSame([], self::service()->get('tenant-1', $this->connection->id));
        self::assertSame(
            ['evidence.acr', 'evidence.amr', 'evidence.combinations'],
            self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser())->changedSettings,
        );
        self::assertTrue(SettingRules::isSame(self::POLICY, self::service()->get('tenant-1', $this->connection->id)));
    }

    /**
     * A change voids no request, code or reservation, and the code is judged by
     * the new policy.
     *
     * @return void
     */
    public function testNothingInFlightIsTouched(): void
    {
        $this->app?->bind(EvidencePolicy::class, ConnectionEvidencePolicy::class);

        $start      = $this->start();
        $completion = $this->complete();
        $link       = Link::query()->sole();
        $code       = HandoffCode::query()->sole();

        $this->start();

        self::assertSame(LinkState::RESERVED, $link->state);
        self::assertSame(
            ['evidence.acr', 'evidence.amr', 'evidence.combinations'],
            self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser())->changedSettings,
        );

        self::assertSame($link->id, Link::query()->sole()->id);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertNull(HandoffCode::query()->whereKey($code->id)->sole()->voided_at);
        self::assertSame(2, AuthorizationRequest::query()->whereNull('voided_at')->count());
        self::assertTrue($this->admit($completion, $start)->isAdmitted());
    }

    /**
     * A code issued before the change is judged at its redemption by the policy
     * written.
     *
     * @return void
     */
    public function testAPolicySetAfterCompletionDecidesTheRedemption(): void
    {
        $this->app?->bind(EvidencePolicy::class, ConnectionEvidencePolicy::class);

        app(LinkStore::class)->create(
            $this->connection,
            new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT),
            $this->person,
            LinkOrigin::PROVISIONING,
            Clients::browser(),
        );

        $start = $this->start();

        $context = new AuthenticationContext($this->clock->now(), ['pwd', 'otp']);

        $this->verifying->claims = new VerifiedClaims(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT, null, ['mail' => self::EMAIL], $context);

        $completion = $this->complete();

        self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser());

        self::assertSame(['pwd', 'otp'], $this->admit($completion, $start)->evidence?->methods());
    }

    /**
     * Rows of `[protocol, policy, the violations]`: what is given, judged for
     * the protocol of the connection, in whole.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, mixed>, 2: list<array{0: string, 1: string}>}>
     */
    public static function provideInvalidPolicies(): iterable
    {
        yield 'an unknown name' => [VerifyingDriver::NAME, ['max_age' => 5] + self::POLICY, [['max_age', 'unknown']]];
        yield 'a maximum age above the ceiling' => [VerifyingDriver::NAME, ['max_age_seconds' => 901] + self::POLICY, [['max_age_seconds', 'not_allowed']]];
        yield 'a maximum age of nothing' => [VerifyingDriver::NAME, ['max_age_seconds' => 0] + self::POLICY, [['max_age_seconds', 'not_allowed']]];
        yield 'a maximum age below nothing' => [VerifyingDriver::NAME, ['max_age_seconds' => -1] + self::POLICY, [['max_age_seconds', 'not_allowed']]];
        yield 'a maximum age as a string' => [VerifyingDriver::NAME, ['max_age_seconds' => '60'] + self::POLICY, [['max_age_seconds', 'invalid_type']]];
        yield 'an unregistered method' => [VerifyingDriver::NAME, ['amr' => ['none']], [['amr.0', 'not_allowed'], ['combinations', 'required']]];
        yield 'no combinations' => [VerifyingDriver::NAME, ['amr' => ['pwd']], [['combinations', 'required']]];
        yield 'a combination naming nothing' => [VerifyingDriver::NAME, ['amr' => ['pwd'], 'combinations' => [[]]], [['combinations.0', 'required']]];
        yield 'too many classes' => [VerifyingDriver::NAME, ['acr' => array_fill(0, 33, 'c')] + self::POLICY, [['acr', 'too_many'], ['combinations.1.acr', 'not_allowed']]];
        yield 'a SAML class over OIDC' => ['oidc', self::SAML_POLICY, [['authn_context_class_ref', 'unsupported'], ['combinations.0.authn_context_class_ref', 'unsupported']]];
        yield 'a method over SAML' => ['saml2', ['amr' => ['pwd'], 'combinations' => [['amr' => ['pwd']]]], [['amr', 'unsupported'], ['combinations.0.amr', 'unsupported']]];
        yield 'a class over SAML' => ['saml2', ['acr' => ['c'], 'combinations' => [['acr' => 'c']]], [['acr', 'unsupported'], ['combinations.0.acr', 'unsupported']]];
    }

    /**
     * What is invalid is refused with every violation, and writes and reports
     * nothing.
     *
     * @param  string  $protocol
     * @param  array<array-key, mixed>  $policy
     * @param  list<array{0: string, 1: string}>  $violations
     * @return void
     */
    #[DataProvider('provideInvalidPolicies')]
    public function testWhatIsInvalidIsRefused(string $protocol, array $policy, array $violations): void
    {
        $connection = $this->makeConnection(['protocol' => $protocol, 'settings' => [$protocol === 'saml2' ? 'idp_entity_id' : 'issuer' => VerifyingDriver::ISSUER]]);
        $result     = self::service()->set('tenant-1', $connection->id, $policy, Clients::browser());

        self::assertSame(ConnectionStatus::INVALID, $result->status);
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame($violations, self::violations($result));
        self::assertNull(self::column($connection->id));

        $this->assertEventSequence([]);
    }

    /**
     * Rows of `[the connection's own maximum age]`: the least, and the ceiling
     * itself, each accepted.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideAcceptedMaximumAges(): iterable
    {
        yield 'one second' => [1];
        yield 'one under the ceiling' => [899];
        yield 'the ceiling' => [900];
    }

    /**
     * A maximum age up to the ceiling is written, and named when it changes.
     *
     * @param  int  $age
     * @return void
     */
    #[DataProvider('provideAcceptedMaximumAges')]
    public function testAMaximumAgeUpToTheCeilingIsWritten(int $age): void
    {
        $result = self::service()->set('tenant-1', $this->connection->id, ['max_age_seconds' => $age] + self::POLICY, Clients::browser());

        self::assertTrue($result->isChanged());
        self::assertSame($age, app(EvidenceSettingsService::class)->get('tenant-1', $this->connection->id)['max_age_seconds'] ?? null);
    }

    /**
     * The ceiling is read when the policy is written: lowering it refuses a
     * value it accepted before, which stays as stored until it is replaced.
     *
     * @return void
     */
    public function testTheCeilingIsReadAtWriteTime(): void
    {
        self::assertTrue(self::service()->set('tenant-1', $this->connection->id, ['max_age_seconds' => 800] + self::POLICY, Clients::browser())->isChanged());

        config()->set('sso.linking.evidence_max_age_seconds', 700);

        $result = self::service()->set('tenant-1', $this->connection->id, ['max_age_seconds' => 701] + self::POLICY, Clients::browser());

        self::assertSame(ConnectionStatus::INVALID, $result->status);
        self::assertSame([['max_age_seconds', 'not_allowed']], self::violations($result));
        self::assertSame(800, app(EvidenceSettingsService::class)->get('tenant-1', $this->connection->id)['max_age_seconds'] ?? null);
        self::assertTrue(self::service()->set('tenant-1', $this->connection->id, ['max_age_seconds' => 700] + self::POLICY, Clients::browser())->isChanged());
    }

    /**
     * A SAML connection's policy is written for SAML.
     *
     * @return void
     */
    public function testASamlPolicyIsWritten(): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2', 'settings' => ['idp_entity_id' => VerifyingDriver::ISSUER]]);
        $result     = self::service()->set('tenant-1', $connection->id, self::SAML_POLICY, Clients::browser());

        self::assertSame(['evidence.authn_context_class_ref', 'evidence.combinations'], $result->changedSettings);
        self::assertTrue(SettingRules::isSame(self::SAML_POLICY, self::service()->get('tenant-1', $connection->id)));
    }

    /**
     * A violation names the path and never the value given.
     *
     * @return void
     */
    public function testAViolationNeverEchoesTheValue(): void
    {
        $result = self::service()->set(
            'tenant-1',
            $this->connection->id,
            ['acr' => [self::CLASS_VALUE . "\x01"], 'combinations' => [['acr' => self::CLASS_VALUE]]],
            Clients::browser(),
        );

        self::assertSame([['acr.0', 'invalid_format'], ['combinations.0.acr', 'not_allowed']], self::violations($result));
        self::assertStringNotContainsString(self::CLASS_VALUE, (string) json_encode($result));
        self::assertStringNotContainsString(self::CLASS_VALUE, print_r($result, true));
    }

    /**
     * What is given is a sensitive parameter, so no trace shows it.
     *
     * @return void
     */
    public function testWhatIsGivenIsASensitiveParameter(): void
    {
        $parameter = (new \ReflectionMethod(EvidenceSettingsService::class, 'set'))->getParameters()[2];

        self::assertSame('policy', $parameter->getName());
        self::assertCount(1, $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * Stale authentication is refused before anything is judged or written, and
     * reports nothing.
     *
     * @return void
     */
    public function testStaleAuthenticationIsRefused(): void
    {
        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        $result = self::service()->set('tenant-1', $this->connection->id, ['amr' => 'not-a-list'], Clients::browser());

        self::assertSame(ConnectionStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame([], $result->violations);
        self::assertNull(self::column($this->connection->id));

        $this->assertEventSequence([]);
    }

    /**
     * An unknown connection, another tenant's and one differing by case are the
     * same refusal, before freshness is asked.
     *
     * @return void
     */
    public function testAnotherTenantsConnectionIsNotFound(): void
    {
        foreach ([['tenant-2', $this->connection->id], ['TENANT-1', $this->connection->id], ['tenant-1', '01jbexampleconnection00000']] as [$tenant, $id]) {

            $result = self::service()->set($tenant, $id, self::POLICY, Clients::browser());

            self::assertSame(ConnectionStatus::REFUSED, $result->status);
            self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $result->reason);
        }

        $this->freshness->assertNotAsked();
        self::assertNull(self::column($this->connection->id));

        $this->assertEventSequence([]);
    }

    /**
     * A connection gone between the plain read and the lock is not found.
     *
     * @return void
     */
    public function testAConnectionGoneBeforeTheLockIsNotFound(): void
    {
        $id = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'settings' => ['issuer' => VerifyingDriver::ISSUER]])->id;

        $this->beforeTheNextTransaction(static fn (): mixed => Connection::query()->whereKey($id)->delete());

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, self::service()->set('tenant-1', $id, self::POLICY, Clients::browser())->reason);

        $this->assertEventSequence([]);
    }

    /**
     * Rows of `[what is switched off, protocol]`: a protocol no longer
     * available refuses the change, whatever was given.
     *
     * @return iterable<string, array{0: ?string, 1: string}>
     */
    public static function provideUnavailableProtocols(): iterable
    {
        yield 'no such driver' => [null, 'nonesuch'];
        yield 'its feature off' => ['sso.features.saml2', 'saml2'];
    }

    /**
     * A protocol no longer available refuses the change.
     *
     * @param  ?string  $feature
     * @param  string  $protocol
     * @return void
     */
    #[DataProvider('provideUnavailableProtocols')]
    public function testAnUnavailableProtocolIsRefused(?string $feature, string $protocol): void
    {
        $connection = $this->makeConnection(['protocol' => $protocol]);

        if ($feature !== null) {
            config()->set($feature, false);
        }

        $result = self::service()->set('tenant-1', $connection->id, ['not' => 'judged'], Clients::browser());

        self::assertSame(ConnectionStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $result->reason);
        self::assertNull(self::column($connection->id));

        $this->assertEventSequence([]);
    }

    /**
     * An empty tenant id is the caller's mistake, on both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEmptyTenantIdThrows(): void
    {
        $attempts = [
            fn (): mixed => self::service()->get('', $this->connection->id),
            fn (): mixed => self::service()->set('', $this->connection->id, self::POLICY, Clients::browser()),
        ];

        foreach ($attempts as $attempt) {
            try {
                $attempt();
                self::fail('An empty tenant id was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A tenant id is 1 to 255 bytes.', $exception->getMessage());
            }
        }
    }

    /**
     * Nothing is logged.
     *
     * @return void
     */
    public function testNothingIsLogged(): void
    {
        $this->captureLogs();

        self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser());
        self::service()->set('tenant-1', $this->connection->id, ['acr' => [self::CLASS_VALUE . "\x01"]], Clients::browser());

        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * A change the caller's transaction rolls back writes nothing and reports
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackChangeReportsNothing(): void
    {
        $database = DB::connection(StorageConnection::name());

        try {
            $database->transaction(function (): void {
                self::assertTrue(self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser())->isChanged());

                throw new \RuntimeException('The caller failed.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The caller failed.', $exception->getMessage());
        }

        self::assertNull(self::column($this->connection->id));

        $this->assertEventSequence([]);
    }

    /**
     * The only lock taken is the connection's row, the first a redemption
     * locks.
     *
     * @return void
     */
    public function testTheOnlyLockIsTheRowARedemptionLocksFirst(): void
    {
        app(LinkStore::class)->create(
            $this->connection,
            new LinkSubject(VerifyingDriver::ISSUER, VerifyingDriver::SUBJECT),
            $this->person,
            LinkOrigin::PROVISIONING,
            Clients::browser(),
        );

        $start      = $this->start();
        $completion = $this->complete();
        $row        = 'connections ' . $this->connection->id . ', tenant-1';

        $this->recordLockOrder();

        self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser());

        self::assertSame([$row], $this->lockOrder());

        self::service()->set('tenant-1', $this->connection->id, self::POLICY, Clients::browser());
        self::service()->set('tenant-1', $this->connection->id, ['other' => true], Clients::browser());

        self::assertSame([$row, $row, $row], $this->lockOrder());
        self::assertSame(0, $this->enforcementStatements());

        self::assertTrue($this->admit($completion, $start)->isAdmitted());
        self::assertSame([$row, $row, $row, $row, 'code', 'link'], $this->lockOrder());
    }

    /**
     * The helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\EvidenceSettingsService
     */
    private static function service(): EvidenceSettingsService
    {
        return app(EvidenceSettingsService::class);
    }

    /**
     * Each violation of the result, as its setting and code.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @return list<array{0: string, 1: string}>
     */
    private static function violations(ConnectionResult $result): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $result->violations);
    }

    /**
     * What the column holds, as stored.
     *
     * @param  string  $connectionId
     * @return mixed
     */
    private static function column(string $connectionId): mixed
    {
        return DB::connection(StorageConnection::name())->table(StorageConnection::table('connections.table'))->where('id', $connectionId)->value('evidence_policy');
    }

    /**
     * Write the column, as something else than the package might.
     *
     * @param  string  $connectionId
     * @param  string  $json
     * @return void
     */
    private static function writeColumn(string $connectionId, string $json): void
    {
        DB::connection(StorageConnection::name())->table(StorageConnection::table('connections.table'))->where('id', $connectionId)->update(['evidence_policy' => $json]);
    }
}
