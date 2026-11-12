<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;

/**
 * Unit tests for the OIDC settings and how a change to each is classified.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OidcSetting::class)]
final class OidcSettingTest extends TestCase
{
    /**
     * The names are these, in this order: a name is never renamed or reused.
     *
     * @return void
     */
    public function testTheNamesAreStable(): void
    {
        self::assertSame([
            'issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'returns_iss',
            'client_id', 'client_secret', 'client_authentication', 'client_assertion_algorithm', 'scopes', 'id_token_algorithms', 'extra_parameters',
            'trusted_audiences', 'max_age', 'fetch_userinfo', 'metadata_refresh',
        ], array_column(OidcSetting::cases(), 'value'));
    }

    /**
     * Every setting but the scopes and the extra parameters is trust.
     *
     * @return void
     */
    public function testEveryChangeButTheRequestOptionsIsTrust(): void
    {
        foreach (OidcSetting::cases() as $setting) {

            $expected = in_array($setting, [OidcSetting::SCOPES, OidcSetting::EXTRA_PARAMETERS], true) ? null : FreshnessOperation::CONNECTION_TRUST;

            self::assertSame($expected, $setting->freshness(), $setting->value);
        }
    }

    /**
     * The issuer and the client id may change what existing subjects mean; the
     * client secret is the one secret.
     *
     * @return void
     */
    public function testTheSubjectAndSecretSettings(): void
    {
        self::assertSame(['issuer', 'client_id'], OidcSetting::subjectNames());
        self::assertTrue(OidcSetting::ISSUER->altersSubject());
        self::assertFalse(OidcSetting::SCOPES->altersSubject());
        self::assertSame(['client_secret'], OidcSetting::secretNames());
        self::assertTrue(OidcSetting::CLIENT_SECRET->isSecret());
        self::assertFalse(OidcSetting::CLIENT_ID->isSecret());
    }
}
