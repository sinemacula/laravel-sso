<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use Tests\Concerns\TreatsWarningsAsErrors;
use Tests\Fixtures\Protocols\IdentifiedConnection;

/**
 * Unit tests for an OIDC connection's typed options (SSO-2.4): every setting
 * read with its default applied, and a setting a complete connection holds
 * refused as the caller's mistake when it is missing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OidcOptions::class)]
final class OidcOptionsTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /**
     * Every setting given is read as given.
     *
     * @return void
     */
    public function testEverySettingIsReadAsGiven(): void
    {
        $options = OidcOptions::of(new IdentifiedConnection('c1', settings: [
            'issuer'                 => 'https://op.example.test/t/',
            'authorization_endpoint' => 'https://op.example.test/authorize',
            'token_endpoint'         => 'https://op.example.test/token',
            'jwks_uri'               => 'https://op.example.test/jwks',
            'userinfo_endpoint'      => 'https://op.example.test/userinfo',
            'returns_iss'            => true,
            'client_id'              => 'client-1',
            'client_authentication'  => 'private_key_jwt',
            'scopes'                 => ['openid', 'email'],
            'id_token_algorithms'    => ['PS256', 'ES256'],
            'extra_parameters'       => ['prompt' => 'login', 'login_hint' => 'a@example.com'],
            'trusted_audiences'      => ['api'],
            'max_age'                => 0,
            'fetch_userinfo'         => true,
            'metadata_refresh'       => true,
        ]));

        self::assertSame('https://op.example.test/t/', $options->issuer());
        self::assertSame(
            ['https://op.example.test/authorize', 'https://op.example.test/token', 'https://op.example.test/jwks', 'https://op.example.test/userinfo'],
            [$options->authorizationEndpoint(), $options->tokenEndpoint(), $options->jwksUri(), $options->userInfoEndpoint()],
        );
        self::assertSame(['client-1', 'private_key_jwt', true], [$options->clientId(), $options->clientAuthentication(), $options->returnsIss()]);
        self::assertSame(['openid', 'email'], $options->scopes());
        self::assertSame(['PS256', 'ES256'], $options->algorithms()->names);
        self::assertSame(['prompt' => 'login', 'login_hint' => 'a@example.com'], $options->extraParameters());
        self::assertSame([['api'], 0, true, true], [$options->trustedAudiences(), $options->maxAge(), $options->fetchesUserInfo(), $options->refreshes()]);
    }

    /**
     * With nothing given, every default applies and an optional setting is
     * `null`.
     *
     * @return void
     */
    public function testTheDefaultsApply(): void
    {
        $options = OidcOptions::of(new IdentifiedConnection('c1'));

        self::assertSame(['client_secret_basic', false], [$options->clientAuthentication(), $options->returnsIss()]);
        self::assertSame([['openid', 'email', 'profile'], ['RS256']], [$options->scopes(), $options->algorithms()->names]);
        self::assertSame([[], [], null], [$options->extraParameters(), $options->trustedAudiences(), $options->maxAge()]);
        self::assertSame([false, true, null], [$options->fetchesUserInfo(), $options->refreshes(), $options->userInfoEndpoint()]);
        self::assertNull($options->clientAssertionAlgorithm());
    }

    /**
     * A setting a complete connection holds is refused when it is missing, by
     * its name.
     *
     * @return void
     */
    public function testAMissingRequiredSettingIsTheCallersMistake(): void
    {
        $options = OidcOptions::of(new IdentifiedConnection('c1'));
        $reads   = [
            'issuer'                 => $options->issuer(...),
            'authorization_endpoint' => $options->authorizationEndpoint(...),
            'token_endpoint'         => $options->tokenEndpoint(...),
            'jwks_uri'               => $options->jwksUri(...),
            'client_id'              => $options->clientId(...),
        ];

        foreach ($reads as $name => $read) {
            try {
                $read();
                self::fail("A missing [{$name}] was read.");
            } catch (\LogicException $exception) {
                self::assertSame("The connection has no [{$name}]; only a complete connection is used.", $exception->getMessage());
            }
        }
    }

    /**
     * A list setting gives its strings alone, as a list, whatever else it
     * holds, and none for what is not a list.
     *
     * @return void
     */
    public function testAListSettingGivesItsStringsAlone(): void
    {
        $listed = OidcOptions::of(new IdentifiedConnection('c1', settings: ['scopes' => ['openid', 1, null, 'email'], 'trusted_audiences' => 'api']));

        self::assertSame(['openid', 'email'], $listed->scopes());
        self::assertSame([], $listed->trustedAudiences());
    }
}
