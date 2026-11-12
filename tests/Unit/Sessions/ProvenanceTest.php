<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Admission;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use SineMacula\Laravel\Sso\Sessions\ProvenanceDomain;

/**
 * Unit tests for capturing a session's provenance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Provenance::class)]
#[CoversClass(ProvenanceDomain::class)]
final class ProvenanceTest extends TestCase
{
    /** @var string The subject every result asserts. */
    private const string SUBJECT = 'Subject-1 ';

    /** @var string The issuer every result names. */
    private const string ISSUER = 'https://idp.example.com/tenant-issuer';

    /** @var string The provider session id every result asserts. */
    private const string PROVIDER_SESSION = 'provider-session-index-9';

    /**
     * The stored form's version, keys and instant format are fixed.
     *
     * @return void
     */
    public function testTheStoredFormIsFixed(): void
    {
        self::assertSame(1, Provenance::VERSION);
        self::assertSame('saml2', Provenance::SAML2);
        self::assertSame(
            [255, 64, 64, 255, 4096],
            [Provenance::MAX_ID_LENGTH, Provenance::MAX_CONNECTION_ID_LENGTH, Provenance::MAX_VERSION_LENGTH, Provenance::MAX_CONTEXT_LENGTH, Provenance::MAX_STORED_JSON_BYTES],
        );
        self::assertSame('Y-m-d\TH:i:s.u\Z', Provenance::INSTANT_FORMAT);
        self::assertSame([
            'version',
            'connection_id',
            'tenant_id',
            'protocol',
            'provider_auth_time',
            'provider_amr',
            'provider_acr',
            'provider_authn_context_class_ref',
            'link_id',
            'link_provenance',
            'provider_session_deadline',
            'session_not_after',
            'enforcement_version',
        ], Provenance::STORED_KEYS);
    }

    /**
     * An admitted `sign_in` captures every fact, with the result's time.
     *
     * @return void
     */
    public function testAnAdmittedSignInCapturesEveryFact(): void
    {
        $evidence  = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:28:00.000001Z'), ['pwd'], 'urn:example:acr:2');
        $admission = new Admission(RecheckOutcome::PASSED, self::person(), 'link-1', $evidence, LinkOrigin::PROVISIONING, 'enforcement-7');
        $captured  = Provenance::capture(self::verifiedResult('oidc'), $admission, CarbonImmutable::parse('2026-11-01T17:00:00Z'));

        self::assertNotNull($captured);
        self::assertSame([
            'version'                          => 1,
            'connection_id'                    => 'connection-1',
            'tenant_id'                        => 'tenant-1',
            'protocol'                         => 'oidc',
            'provider_auth_time'               => '2026-11-01T09:29:00.123456Z',
            'provider_amr'                     => ['pwd'],
            'provider_acr'                     => 'urn:example:acr:2',
            'provider_authn_context_class_ref' => null,
            'link_id'                          => 'link-1',
            'link_provenance'                  => 'provisioning',
            'provider_session_deadline'        => '2026-11-01T18:00:00.000000Z',
            'session_not_after'                => '2026-11-01T17:00:00.000000Z',
            'enforcement_version'              => 'enforcement-7',
        ], $captured->toArray());
    }

    /**
     * The accepted raw context under each protocol's own name.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: ?string}>
     */
    public static function protocols(): iterable
    {
        yield 'oidc' => ['oidc', 'urn:accepted:context', null];
        yield 'saml2' => ['saml2', null, 'urn:accepted:context'];
        yield 'an application\'s own driver' => ['ldap_bridge', 'urn:accepted:context', null];
        yield 'a driver named like saml2' => ['saml2_bridge', 'urn:accepted:context', null];
        yield 'a driver named like saml' => ['saml', 'urn:accepted:context', null];
    }

    /**
     * Each protocol keeps the raw context under its own name, or none.
     *
     * @param  string  $protocol
     * @param  ?string  $acr
     * @param  ?string  $classRef
     * @return void
     */
    #[DataProvider('protocols')]
    public function testTheRawContextIsKeptUnderItsProtocolsName(string $protocol, ?string $acr, ?string $classRef): void
    {
        $evidence = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd'], 'urn:accepted:context');
        $captured = Provenance::capture(self::verifiedResult($protocol), new Admission(RecheckOutcome::PASSED, self::person(), 'link-1', $evidence), null);

        self::assertSame([$protocol, $acr, $classRef], [$captured?->protocol, $captured?->providerAcr(), $captured?->providerAuthnContextClassRef()]);
    }

    /**
     * Without accepted evidence only the authentication time is kept.
     *
     * @return void
     */
    public function testNothingButTheTimeIsKeptWithoutAcceptedEvidence(): void
    {
        $captured = Provenance::capture(self::verifiedResult('saml2'), new Admission(RecheckOutcome::PASSED, self::person(), 'link-1'), null);

        self::assertSame([[], null, null], [$captured?->providerMethods(), $captured?->providerAcr(), $captured?->providerAuthnContextClassRef()]);
        self::assertSame('2026-11-01T09:29:00.123456Z', $captured?->providerAuthenticatedAt?->format(Provenance::INSTANT_FORMAT));
    }

    /**
     * Accepted evidence stating no raw context keeps none, under any protocol.
     *
     * @return void
     */
    public function testAcceptedEvidenceWithNoRawContextKeepsNone(): void
    {
        $evidence = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd', 'otp']);
        $captured = Provenance::capture(self::verifiedResult('oidc'), new Admission(RecheckOutcome::PASSED, self::person(), 'link-1', $evidence), null);

        self::assertSame([['pwd', 'otp'], null, null], [$captured?->providerMethods(), $captured?->providerAcr(), $captured?->providerAuthnContextClassRef()]);
    }

    /**
     * Raw context classes outside the stored domain, under each protocol.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function unkeptContexts(): iterable
    {
        foreach (['oidc', 'saml2'] as $protocol) {
            yield "{$protocol}: one byte too long" => [$protocol, 'urn:' . str_repeat('a', Provenance::MAX_CONTEXT_LENGTH - 3)];
            yield "{$protocol}: outside ASCII" => [$protocol, 'urn:niveau:élevé'];
            yield "{$protocol}: a control character" => [$protocol, "urn:class\n"];
            yield "{$protocol}: a delete" => [$protocol, "urn:class\x7F"];
            yield "{$protocol}: not UTF-8" => [$protocol, "urn:\xFF"];
        }
    }

    /**
     * A raw context outside the stored domain is kept as `null`, not refused.
     *
     * @param  string  $protocol
     * @param  string  $raw
     * @return void
     */
    #[DataProvider('unkeptContexts')]
    public function testARawContextOutsideTheStoredDomainIsKeptAsNull(string $protocol, string $raw): void
    {
        $evidence = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd', 'otp'], $raw);
        $captured = Provenance::capture(self::verifiedResult($protocol), new Admission(RecheckOutcome::PASSED, self::person(), 'link-1', $evidence), null);

        self::assertSame([['pwd', 'otp'], null, null], [$captured?->providerMethods(), $captured?->providerAcr(), $captured?->providerAuthnContextClassRef()]);
        self::assertSame('link-1', $captured?->linkId);
    }

    /**
     * A raw context of exactly `MAX_CONTEXT_LENGTH` bytes is kept.
     *
     * @return void
     */
    public function testARawContextAtItsLimitIsKept(): void
    {
        $raw      = 'urn:' . str_repeat('~', Provenance::MAX_CONTEXT_LENGTH - 4);
        $evidence = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd'], $raw);
        $captured = Provenance::capture(self::verifiedResult('oidc'), new Admission(RecheckOutcome::PASSED, self::person(), 'link-1', $evidence), null);

        self::assertSame($raw, $captured?->providerAcr());
    }

    /**
     * Only RFC 8176 registered methods are kept, in order and once each.
     *
     * @return void
     */
    public function testOnlyRegisteredMethodsAreKeptEachOnce(): void
    {
        $evidence = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['hwk', 'urn:custom:passkey', 'pwd', 'hwk', 'PWD', 'mfa'], 'urn:class');
        $captured = Provenance::capture(self::verifiedResult('oidc'), new Admission(RecheckOutcome::PASSED, self::person(), 'link-1', $evidence), null);

        self::assertSame([['hwk', 'pwd', 'mfa'], 'urn:class'], [$captured?->providerMethods(), $captured?->providerAcr()]);
    }

    /**
     * The raw deadline is kept whatever the effective cap.
     *
     * @return void
     */
    public function testTheRawDeadlineIsKeptWhenNoCapWasSet(): void
    {
        $captured = Provenance::capture(self::verifiedResult('saml2'), new Admission(RecheckOutcome::PASSED, self::person(), 'link-1'), null);

        self::assertNotNull($captured);
        self::assertSame('2026-11-01T18:00:00.000000Z', $captured->toArray()['provider_session_deadline']);
        self::assertNull($captured->toArray()['session_not_after']);
        self::assertNull($captured->sessionNotAfter);
    }

    /**
     * An unlinked admission is captured with no link and no link provenance.
     *
     * @return void
     */
    public function testAnUnlinkedAdmissionHasNoLink(): void
    {
        $captured = Provenance::capture(self::verifiedResult('oidc'), new Admission(RecheckOutcome::PASSED), null);

        self::assertSame([null, null], [$captured?->linkId, $captured?->linkProvenance]);
        self::assertSame([null, null], [$captured?->toArray()['link_id'], $captured?->toArray()['link_provenance']]);
    }

    /**
     * A `link` and a `reauthenticate`, which capture nothing.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose}>
     */
    public static function otherPurposes(): iterable
    {
        yield 'link' => [Purpose::LINK];
        yield 'reauthenticate' => [Purpose::REAUTHENTICATE];
    }

    /**
     * Another purpose captures nothing, even admitted with evidence and a link.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('otherPurposes')]
    public function testAnotherPurposeCapturesNothing(Purpose $purpose): void
    {
        $evidence  = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd'], 'urn:class');
        $admission = new Admission(RecheckOutcome::PASSED, self::person(), 'link-1', $evidence, LinkOrigin::LINK_PURPOSE, 'enforcement-1');

        self::assertNull(Provenance::capture(self::verifiedResult('oidc', $purpose), $admission, CarbonImmutable::parse('2026-11-01T17:00:00Z')));
    }

    /**
     * Every refusing outcome.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome}>
     */
    public static function refusals(): iterable
    {
        foreach (RecheckOutcome::cases() as $outcome) {

            if ($outcome === RecheckOutcome::PASSED) {
                continue;
            }

            yield $outcome->value => [$outcome];
        }
    }

    /**
     * An admission that did not pass captures nothing, whatever it carries.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome  $outcome
     * @return void
     */
    #[DataProvider('refusals')]
    public function testARefusedAdmissionCapturesNothing(RecheckOutcome $outcome): void
    {
        self::assertNull(Provenance::capture(self::verifiedResult('oidc'), new Admission($outcome, self::person(), 'link-1', null, LinkOrigin::PROVISIONING, 'v'), null));
    }

    /**
     * Nothing about the person or the provider session is captured.
     *
     * @return void
     */
    public function testNothingAboutThePersonIsCaptured(): void
    {
        $evidence = new AcceptedEvidence('connection-1', CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd'], 'urn:class');
        $admitted = new Admission(RecheckOutcome::PASSED, self::person(), 'link-1', $evidence, LinkOrigin::PROVISIONING, 'v');
        $captured = Provenance::capture(self::verifiedResult('saml2'), $admitted, null);
        $stored   = (string) json_encode($captured?->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        foreach ([self::SUBJECT, self::ISSUER, self::PROVIDER_SESSION, 'person@example.com', 'staff', 'admins', 'App\\\Models\\\User', '"42"'] as $value) {
            self::assertStringNotContainsString($value, $stored);
        }
    }

    /**
     * The person a result's link resolved to.
     *
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    private static function person(): IdentityReference
    {
        return new IdentityReference('App\Models\User', '42');
    }

    /**
     * A verified result with a full authentication context.
     *
     * @param  string  $protocol
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private static function verifiedResult(string $protocol, Purpose $purpose = Purpose::SIGN_IN): VerifiedResult
    {
        return new VerifiedResult(
            issuer: self::ISSUER,
            subject: self::SUBJECT,
            nameIdFormat: null,
            connectionId: 'connection-1',
            tenantId: 'tenant-1',
            protocol: $protocol,
            application: 'web',
            purpose: $purpose,
            requestReference: RequestReference::fromString('ref0ref1ref2ref3ref4ref5ref6ref7'),
            attributes: ['email' => 'person@example.com', 'groups' => ['staff', 'admins']],
            emailDomainVerified: true,
            authenticationContext: new AuthenticationContext(
                CarbonImmutable::parse('2026-11-01T09:29:00.123456Z'),
                ['pwd', 'otp', 'hwk'],
                'urn:asserted:but:not:accepted',
                self::PROVIDER_SESSION,
                CarbonImmutable::parse('2026-11-01T18:00:00Z'),
            ),
        );
    }
}
