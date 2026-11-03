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
 * Unit tests for the package's contribution to the authentication context
 * (SSO-9.7): every `sso.*` key with its exact name, value and type; no key at
 * all for a session with no provenance, and every key, `null` where unstated,
 * for one with it; instants as UTC `CarbonImmutable`s to the microsecond, the
 * link's provenance as its enum value; nothing about the person; and a stored
 * form this version did not write refused rather than read as none.
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
     * A session with no provenance from the package contributes nothing: no
     * `sso.*` key at all, whether given as none or as nothing stored.
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
            [self::instant($context['sso.provider_auth_time']), self::instant($context['sso.provider_session_deadline']), self::instant($context['sso.session_not_after'])],
        );
    }

    /**
     * A SAML sign-in's raw context is projected under its own key, never as
     * `sso.provider_acr`.
     *
     * @return void
     */
    public function testASamlContextClassHasItsOwnKey(): void
    {
        $context = AuthenticationContext::of(new Provenance('connection-1', 'tenant-1', 'saml2', authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'));

        self::assertSame(['urn:oasis:names:tc:SAML:2.0:ac:classes:Password', null], [$context['sso.provider_authn_context_class_ref'], $context['sso.provider_acr']]);
    }

    /**
     * A provenance with only what every one has contributes every key, `null`
     * for each fact not stated and no methods: a key present with `null` is a
     * session established through the package without that fact.
     *
     * @return void
     */
    public function testAnUnstatedFactIsNullAndStillPresent(): void
    {
        self::assertSame([
            'sso.connection'                       => 'connection-1',
            'sso.tenant'                           => 'tenant-1',
            'sso.protocol'                         => 'a-custom-driver',
            'sso.provider_auth_time'               => null,
            'sso.provider_amr'                     => [],
            'sso.provider_acr'                     => null,
            'sso.provider_authn_context_class_ref' => null,
            'sso.link'                             => null,
            'sso.link_provenance'                  => null,
            'sso.provider_session_deadline'        => null,
            'sso.session_not_after'                => null,
            'sso.enforcement_version'              => null,
        ], AuthenticationContext::of(new Provenance('connection-1', 'tenant-1', 'a-custom-driver')));
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
     * Every value is a PHP scalar, a list of strings, `null` or a UTC
     * `CarbonImmutable`: no type of the package crosses the seam.
     *
     * @return void
     */
    public function testNoValueIsATypeOfThePackage(): void
    {
        foreach (AuthenticationContext::of(self::oidc()) as $key => $value) {

            $allowed = $value === null || is_scalar($value) || (is_array($value) && array_is_list($value) && array_filter($value, is_string(...)) === $value);

            if ($value instanceof CarbonImmutable) {
                $allowed = $value->getTimezone()->getName() === 'UTC';
            }

            self::assertTrue($allowed, "{$key} is not a plain value.");
        }
    }

    /**
     * What a session stored is projected exactly as the provenance it was,
     * including through JSON with its keys in another order.
     *
     * @return void
     */
    public function testTheStoredFormProjectsAsTheProvenance(): void
    {
        $stored = array_reverse((array) json_decode((string) json_encode(self::oidc()->toArray()), true), true);

        self::assertEquals(AuthenticationContext::of(self::oidc()), AuthenticationContext::fromStored($stored));
        self::assertSame(AuthenticationContext::KEYS, array_keys(AuthenticationContext::fromStored($stored)));
    }

    /**
     * A stored form this version did not write is refused, never projected as
     * no contribution.
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
     * Nothing about the person or their provider session is projected: no key
     * names one, and the projection is exactly the twelve keys.
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
     * The projection is pure: the same provenance projects the same keys and
     * values each time, and the provenance is unchanged by it.
     *
     * @return void
     */
    public function testTheProjectionIsPure(): void
    {
        $provenance = self::oidc();
        $before     = $provenance->toArray();

        self::assertEquals(AuthenticationContext::of($provenance), AuthenticationContext::of($provenance));
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
     * The projected instant in the stored form, refusing anything that is not a
     * UTC `CarbonImmutable`.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function instant(mixed $value): string
    {
        self::assertInstanceOf(CarbonImmutable::class, $value);
        self::assertSame('UTC', $value->getTimezone()->getName());

        return $value->format('Y-m-d\TH:i:s.u\Z');
    }
}
