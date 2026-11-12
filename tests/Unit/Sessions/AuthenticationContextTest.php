<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;
use SineMacula\Laravel\Sso\Sessions\Provenance;

/**
 * Unit tests for the package's `sso.*` authentication context keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationContext::class)]
final class AuthenticationContextTest extends TestCase
{
    /**
     * The namespace and every key are named exactly, and stable.
     *
     * @return void
     */
    public function testEveryKeyIsNamedExactly(): void
    {
        self::assertSame('sso', AuthenticationContext::NAMESPACE);
        self::assertSame([
            'sso.connection',
            'sso.tenant',
            'sso.protocol',
            'sso.provider_auth_time',
            'sso.provider_amr',
            'sso.provider_acr',
            'sso.provider_authn_context_class_ref',
            'sso.link',
            'sso.link_provenance',
            'sso.provider_session_deadline',
            'sso.session_not_after',
            'sso.enforcement_version',
        ], AuthenticationContext::KEYS);
        self::assertSame(
            AuthenticationContext::KEYS,
            [
                AuthenticationContext::CONNECTION,
                AuthenticationContext::TENANT,
                AuthenticationContext::PROTOCOL,
                AuthenticationContext::PROVIDER_AUTH_TIME,
                AuthenticationContext::PROVIDER_AMR,
                AuthenticationContext::PROVIDER_ACR,
                AuthenticationContext::PROVIDER_AUTHN_CONTEXT_CLASS_REF,
                AuthenticationContext::LINK,
                AuthenticationContext::LINK_PROVENANCE,
                AuthenticationContext::PROVIDER_SESSION_DEADLINE,
                AuthenticationContext::SESSION_NOT_AFTER,
                AuthenticationContext::ENFORCEMENT_VERSION,
            ],
        );
    }

    /**
     * Every key fits the form an authentication context holds keys in.
     *
     * @return void
     */
    public function testEveryKeyFitsTheContextsKeyForm(): void
    {
        self::assertMatchesRegularExpression('/^[a-z][a-z0-9_]{0,31}$/D', AuthenticationContext::NAMESPACE);

        foreach (AuthenticationContext::KEYS as $key) {
            self::assertStringStartsWith(AuthenticationContext::NAMESPACE . '.', $key);
            self::assertMatchesRegularExpression('/^[a-z][a-z0-9_]{0,63}$/D', substr($key, strlen(AuthenticationContext::NAMESPACE) + 1), $key);
        }
    }

    /**
     * A session without provenance contributes no `sso.*` key.
     *
     * @return void
     */
    public function testNoProvenanceContributesNothing(): void
    {
        self::assertSame([], AuthenticationContext::of(null));
        self::assertSame([], AuthenticationContext::fromStored(null));
    }

    /**
     * A provenance with every fact contributes every key, with its value.
     *
     * @return void
     */
    public function testEveryFactIsProjectedUnderItsKey(): void
    {
        $context = AuthenticationContext::of(self::oidc());

        self::assertSame(AuthenticationContext::KEYS, array_keys($context));
        self::assertSame('connection-1', $context['sso.connection']);
        self::assertSame('tenant-1', $context['sso.tenant']);
        self::assertSame('oidc', $context['sso.protocol']);
        self::assertSame(['pwd', 'otp'], $context['sso.provider_amr']);
        self::assertSame('urn:example:acr:2', $context['sso.provider_acr']);
        self::assertNull($context['sso.provider_authn_context_class_ref']);
        self::assertSame('link-1', $context['sso.link']);
        self::assertSame('provisioning', $context['sso.link_provenance']);
        self::assertSame('enforcement-7', $context['sso.enforcement_version']);
        self::assertSame(
            ['2026-11-01T09:29:00.123456Z', '2026-11-01T18:00:00.000000Z', '2026-11-01T17:00:00.000000Z'],
            [$context['sso.provider_auth_time'], $context['sso.provider_session_deadline'], $context['sso.session_not_after']],
        );
    }

    /**
     * Each instant is a UTC string to the microsecond.
     *
     * @return void
     */
    public function testEachInstantIsAUtcStringToTheMicrosecond(): void
    {
        $context = AuthenticationContext::of(new Provenance(
            'connection-1',
            'tenant-1',
            'oidc',
            CarbonImmutable::parse('2026-11-01T04:29:00.000001-05:00'),
            providerSessionDeadline: CarbonImmutable::parse('2026-11-02T00:59:59.999999+01:00'),
            sessionNotAfter: CarbonImmutable::parse('2026-11-01T23:59:59Z'),
        ));

        self::assertSame(
            ['2026-11-01T09:29:00.000001Z', '2026-11-01T23:59:59.999999Z', '2026-11-01T23:59:59.000000Z'],
            [$context['sso.provider_auth_time'], $context['sso.provider_session_deadline'], $context['sso.session_not_after']],
        );
    }

    /**
     * A SAML raw context has its own key, never `sso.provider_acr`.
     *
     * @return void
     */
    public function testASamlContextClassHasItsOwnKey(): void
    {
        $context = AuthenticationContext::of(new Provenance('connection-1', 'tenant-1', 'saml2', authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'));

        self::assertSame(['urn:oasis:names:tc:SAML:2.0:ac:classes:Password', null], [$context['sso.provider_authn_context_class_ref'], $context['sso.provider_acr']]);
    }

    /**
     * An unstated fact is present as `null`.
     *
     * @return void
     */
    public function testAnUnstatedFactIsNullAndStillPresent(): void
    {
        self::assertSame([
            'sso.connection'                       => 'connection-1',
            'sso.tenant'                           => 'tenant-1',
            'sso.protocol'                         => 'a_custom_driver',
            'sso.provider_auth_time'               => null,
            'sso.provider_amr'                     => [],
            'sso.provider_acr'                     => null,
            'sso.provider_authn_context_class_ref' => null,
            'sso.link'                             => null,
            'sso.link_provenance'                  => null,
            'sso.provider_session_deadline'        => null,
            'sso.session_not_after'                => null,
            'sso.enforcement_version'              => null,
        ], AuthenticationContext::of(new Provenance('connection-1', 'tenant-1', 'a_custom_driver')));
    }

    /**
     * Each link provenance, projected as its enum value.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin, 1: string}>
     */
    public static function origins(): iterable
    {
        yield 'link purpose' => [LinkOrigin::LINK_PURPOSE, 'link_purpose'];
        yield 'provisioning' => [LinkOrigin::PROVISIONING, 'provisioning'];
        yield 'verified domain' => [LinkOrigin::VERIFIED_DOMAIN, 'verified_domain'];
        yield 'migration' => [LinkOrigin::MIGRATION, 'migration'];
    }

    /**
     * The link's provenance is a string, the enum's stable value.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  string  $value
     * @return void
     */
    #[DataProvider('origins')]
    public function testTheLinkProvenanceIsItsEnumValue(LinkOrigin $origin, string $value): void
    {
        self::assertSame($value, AuthenticationContext::of(new Provenance('c', 't', 'p', linkId: 'link-1', linkProvenance: $origin))['sso.link_provenance']);
    }

    /**
     * A provenance with every optional part, and one with none.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Sessions\Provenance}>
     */
    public static function provenances(): iterable
    {
        yield 'every part' => [self::oidc()];
        yield 'every optional part null' => [new Provenance('connection-1', 'tenant-1', 'a_custom_driver')];
    }

    /**
     * Every value is `null`, a scalar or a list of scalars.
     *
     * @param  \SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return void
     */
    #[DataProvider('provenances')]
    public function testEveryValueIsPlain(Provenance $provenance): void
    {
        $projections = ['of' => AuthenticationContext::of($provenance), 'fromStored' => AuthenticationContext::fromStored($provenance->toArray())];

        foreach ($projections as $projection => $context) {

            self::assertSame(AuthenticationContext::KEYS, array_keys($context), $projection);

            foreach ($context as $key => $value) {
                self::assertTrue(self::isPlain($value), "{$projection}: {$key} is not a plain value.");
            }
        }
    }

    /**
     * A provenance and its stored form project identically.
     *
     * @param  \SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return void
     */
    #[DataProvider('provenances')]
    public function testAProvenanceAndItsStoredFormProjectIdentically(Provenance $provenance): void
    {
        self::assertSame(AuthenticationContext::of($provenance), AuthenticationContext::fromStored($provenance->toArray()));
    }

    /**
     * A stored form projects as its provenance, even with reordered JSON keys.
     *
     * @return void
     */
    public function testTheStoredFormProjectsAsTheProvenance(): void
    {
        $stored = array_reverse((array) json_decode((string) json_encode(self::oidc()->toArray()), true), true);

        self::assertSame(AuthenticationContext::of(self::oidc()), AuthenticationContext::fromStored($stored));
        self::assertSame(AuthenticationContext::KEYS, array_keys(AuthenticationContext::fromStored($stored)));
    }

    /**
     * Stored forms this version did not write.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function corruptions(): iterable
    {
        yield 'nothing' => [[]];
        yield 'another version' => [array_replace(self::oidc()->toArray(), ['version' => 2])];
        yield 'a subject added' => [[...self::oidc()->toArray(), 'subject' => 'Subject-1']];
    }

    /**
     * Each such form is an `UnexpectedValueException`.
     *
     * @param  array<string, mixed>  $stored
     * @return void
     */
    #[DataProvider('corruptions')]
    public function testACorruptStoredFormIsRefused(array $stored): void
    {
        $this->expectException(\UnexpectedValueException::class);

        AuthenticationContext::fromStored($stored);
    }

    /**
     * Nothing about the person is projected; there are exactly twelve keys.
     *
     * @return void
     */
    public function testNothingAboutThePersonIsProjected(): void
    {
        $keys = array_keys(AuthenticationContext::of(self::oidc()));

        self::assertCount(12, $keys);

        foreach (['subject', 'issuer', 'email', 'group', 'attribute', 'token', 'session_id', 'sid', 'name_id'] as $forbidden) {
            self::assertSame([], array_filter($keys, static fn (string $key): bool => str_contains($key, $forbidden)), $forbidden);
        }
    }

    /**
     * The projection is pure.
     *
     * @return void
     */
    public function testTheProjectionIsPure(): void
    {
        $provenance = self::oidc();
        $before     = $provenance->toArray();

        self::assertSame(AuthenticationContext::of($provenance), AuthenticationContext::of($provenance));
        self::assertSame($before, $provenance->toArray());
    }

    /**
     * An OIDC provenance with every fact.
     *
     * @return \SineMacula\Laravel\Sso\Sessions\Provenance
     */
    private static function oidc(): Provenance
    {
        return new Provenance(
            'connection-1',
            'tenant-1',
            'oidc',
            CarbonImmutable::parse('2026-11-01T11:29:00.123456+02:00'),
            ['pwd', 'otp'],
            'urn:example:acr:2',
            null,
            'link-1',
            LinkOrigin::PROVISIONING,
            CarbonImmutable::parse('2026-11-01T18:00:00Z'),
            CarbonImmutable::parse('2026-11-01T17:00:00Z'),
            'enforcement-7',
        );
    }

    /**
     * Whether the value is `null`, a scalar, or a list of scalars.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isPlain(mixed $value): bool
    {
        if (is_array($value)) {
            return array_is_list($value) && array_filter($value, is_scalar(...)) === $value;
        }

        return $value === null || is_scalar($value);
    }
}
