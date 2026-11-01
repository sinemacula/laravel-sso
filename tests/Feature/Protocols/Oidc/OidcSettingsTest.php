<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Oidc;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use Tests\TestCase;

/**
 * Feature tests for the OIDC settings (SSO-2.4, SSO-7.1, SSO-7.3): their
 * defaults, every rule with its code and path, the extra parameters that can
 * never set one the flow controls, the client secret that never travels among
 * the settings, completeness, and the classification they take from
 * `OidcSetting`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OidcSettings::class)]
#[CoversClass(SettingRules::class)]
final class OidcSettingsTest extends TestCase
{
    /** @var array<string, string> Every setting a complete connection needs. */
    private const array COMPLETE = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
    ];

    /**
     * Nothing given stores every default, in the order the settings are named.
     *
     * @return void
     */
    public function testAppliesTheDefaults(): void
    {
        $settings = OidcSettings::fromArray([]);

        self::assertSame([
            'returns_iss'           => false,
            'client_authentication' => 'client_secret_basic',
            'scopes'                => ['openid', 'email', 'profile'],
            'id_token_algorithms'   => ['RS256'],
        ], $settings->toArray());

        self::assertSame([], $settings->violations());
    }

    /**
     * What is given is kept exactly as given, the issuer included, in the order
     * the settings are named; a `null` is a setting not given.
     *
     * @return void
     */
    public function testStoresWhatIsGivenExactlyInTheOrderTheSettingsAreNamed(): void
    {
        $stored = OidcSettings::fromArray([
            'client_id'         => 'client-123',
            'scopes'            => null,
            'issuer'            => 'https://IdP.example.com/Tenant/',
            'userinfo_endpoint' => 'https://idp.example.com/userinfo',
            'extra_parameters'  => ['prompt' => 'login'],
        ])->toArray();

        self::assertSame([
            'issuer'                => 'https://IdP.example.com/Tenant/',
            'userinfo_endpoint'     => 'https://idp.example.com/userinfo',
            'returns_iss'           => false,
            'client_id'             => 'client-123',
            'client_authentication' => 'client_secret_basic',
            'scopes'                => ['openid', 'email', 'profile'],
            'id_token_algorithms'   => ['RS256'],
            'extra_parameters'      => ['prompt' => 'login'],
        ], $stored);
    }

    /**
     * Every value the rules allow is accepted.
     *
     * @return void
     */
    public function testAcceptsEveryAllowedValue(): void
    {
        $settings = OidcSettings::fromArray([
            'authorization_endpoint' => 'https://idp.example.com/authorize?tenant=acme',
            'userinfo_endpoint'      => 'https://idp.example.com/userinfo',
            'returns_iss'            => true,
            'client_authentication'  => 'private_key_jwt',
            'scopes'                 => ['openid', 'offline_access', 'https://graph.example.com/user.read', '!#[]~'],
            'id_token_algorithms'    => OidcSettings::ID_TOKEN_ALGORITHMS,
            'extra_parameters'       => array_fill_keys(OidcSettings::EXTRA_PARAMETERS, 'value with spaces'),
        ] + self::COMPLETE);

        self::assertSame([], $settings->violations());
        self::assertTrue($settings->isComplete());

        foreach (OidcSettings::CLIENT_AUTHENTICATIONS as $method) {
            self::assertSame([], OidcSettings::fromArray(['client_authentication' => $method])->violations(), $method);
        }

        self::assertSame([], OidcSettings::fromArray(['scopes' => ['openid', ...array_map(static fn (int $index): string => 'scope' . $index, range(1, 19))]])->violations());
        self::assertSame([], OidcSettings::fromArray(['client_id' => str_repeat('c', 255)])->violations());
        self::assertSame([], OidcSettings::fromArray(['extra_parameters' => []])->violations());
    }

    /**
     * Rows of `[values, violations]`: settings given, and each violation they
     * report as `[setting, code]`, in order.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: list<array{0: string, 1: string}>}>
     */
    public static function provideViolations(): iterable
    {
        $tooManyParameters = [];

        foreach (range(1, 11) as $index) {
            $tooManyParameters['prompt' . $index] = 'x';
        }

        $mostParameters = array_slice($tooManyParameters, 0, 10);
        $eachRefused    = array_map(static fn (string $parameter): array => ['extra_parameters.' . $parameter, 'not_allowed'], array_keys($mostParameters));

        yield from [
            'an issuer that is not a string'  => [['issuer' => true], [['issuer', 'invalid_type']]],
            'an http issuer'                  => [['issuer' => 'http://idp.example.com'], [['issuer', 'not_https']]],
            'an issuer with a query'          => [['issuer' => 'https://idp.example.com/?tenant=1'], [['issuer', 'invalid_format']]],
            'an issuer with a fragment'       => [['issuer' => 'https://idp.example.com/#x'], [['issuer', 'invalid_format']]],
            'an issuer with userinfo'         => [['issuer' => 'https://user@idp.example.com'], [['issuer', 'invalid_format']]],
            'a relative issuer'               => [['issuer' => '/issuer'], [['issuer', 'invalid_format']]],
            'an overlong issuer'              => [['issuer' => 'https://idp.example.com/' . str_repeat('a', 2025)], [['issuer', 'too_long']]],
            'an http authorization endpoint'  => [['authorization_endpoint' => 'http://idp.example.com/authorize'], [['authorization_endpoint', 'not_https']]],
            'an authorization fragment'       => [['authorization_endpoint' => 'https://idp.example.com/authorize#x'], [['authorization_endpoint', 'invalid_format']]],
            'an http token endpoint'          => [['token_endpoint' => 'http://idp.example.com/token'], [['token_endpoint', 'not_https']]],
            'a token endpoint with no host'   => [['token_endpoint' => 'https:///token'], [['token_endpoint', 'invalid_format']]],
            'an http jwks uri'                => [['jwks_uri' => 'http://idp.example.com/jwks'], [['jwks_uri', 'not_https']]],
            'an empty userinfo endpoint'      => [['userinfo_endpoint' => ''], [['userinfo_endpoint', 'required']]],
            'a string for returns iss'        => [['returns_iss' => 'true'], [['returns_iss', 'invalid_type']]],
            'a client id that is a number'    => [['client_id' => 123], [['client_id', 'invalid_type']]],
            'an empty client id'              => [['client_id' => ''], [['client_id', 'required']]],
            'an overlong client id'           => [['client_id' => str_repeat('c', 256)], [['client_id', 'too_long']]],
            'a client id with a control'      => [['client_id' => "client\0"], [['client_id', 'invalid_format']]],
            'a client secret among settings'  => [['client_secret' => 'shh'], [['client_secret', 'reserved']]],
            'a client authentication refused' => [['client_authentication' => 'none'], [['client_authentication', 'not_allowed']]],
            'scopes as a string'              => [['scopes' => 'openid email'], [['scopes', 'invalid_type']]],
            'no scope'                        => [['scopes' => []], [['scopes', 'openid_scope_required']]],
            'scopes without openid'           => [['scopes' => ['email', 'profile']], [['scopes', 'openid_scope_required']]],
            'openid in another case'          => [['scopes' => ['OpenID']], [['scopes', 'openid_scope_required']]],
            'too many scopes'                 => [['scopes' => ['openid', ...array_fill(0, 20, 'x')]], [['scopes', 'too_many']]],
            'a scope twice'                   => [['scopes' => ['openid', 'email', 'email']], [['scopes.2', 'duplicate']]],
            'a scope with a space'            => [['scopes' => ['openid', 'a b']], [['scopes.1', 'invalid_format']]],
            'a scope with a quote'            => [['scopes' => ['openid', 'a"b']], [['scopes.1', 'invalid_format']]],
            'a scope with a backslash'        => [['scopes' => ['openid', 'a\b']], [['scopes.1', 'invalid_format']]],
            'an empty scope'                  => [['scopes' => ['openid', '']], [['scopes.1', 'required']]],
            'an overlong scope'               => [['scopes' => ['openid', str_repeat('s', 256)]], [['scopes.1', 'too_long']]],
            'a scope that is a number'        => [['scopes' => ['openid', 7]], [['scopes.1', 'invalid_type']]],
            'no id token algorithm'           => [['id_token_algorithms' => []], [['id_token_algorithms', 'required']]],
            'the none algorithm'              => [['id_token_algorithms' => ['none']], [['id_token_algorithms.0', 'not_allowed']]],
            'an hmac algorithm'               => [
                ['id_token_algorithms' => ['RS256', 'HS256', 'HS384', 'HS512']],
                [['id_token_algorithms.1', 'not_allowed'], ['id_token_algorithms.2', 'not_allowed'], ['id_token_algorithms.3', 'not_allowed']],
            ],
            'an algorithm in lower case'       => [['id_token_algorithms' => ['rs256']], [['id_token_algorithms.0', 'not_allowed']]],
            'an algorithm twice'               => [['id_token_algorithms' => ['RS256', 'RS256']], [['id_token_algorithms.1', 'duplicate']]],
            'extra parameters as a string'     => [['extra_parameters' => 'prompt=login'], [['extra_parameters', 'invalid_type']]],
            'too many extra parameters'        => [['extra_parameters' => $tooManyParameters], [['extra_parameters', 'too_many']]],
            'a parameter not allowed'          => [['extra_parameters' => ['max_age' => '0']], [['extra_parameters.max_age', 'not_allowed']]],
            'an allowed name in another case'  => [['extra_parameters' => ['Prompt' => 'login']], [['extra_parameters.Prompt', 'not_allowed']]],
            'a parameter that is not a string' => [['extra_parameters' => ['prompt' => ['login']]], [['extra_parameters.prompt', 'invalid_type']]],
            'an overlong parameter'            => [['extra_parameters' => ['login_hint' => str_repeat('h', 513)]], [['extra_parameters.login_hint', 'too_long']]],
            'a parameter with a control'       => [['extra_parameters' => ['login_hint' => "a\r\nb"]], [['extra_parameters.login_hint', 'invalid_format']]],
            'an unnamed parameter'             => [['extra_parameters' => ['' => 'x']], [['extra_parameters', 'not_allowed']]],
            'an unknown setting'               => [['idp_entity_id' => 'https://idp.example.com'], [['idp_entity_id', 'unknown']]],
            'a known setting, then unknown'    => [['issuer' => 'https://idp.example.com', 'unknown' => 1], [['unknown', 'unknown']]],
            'scopes as a map'                  => [['scopes' => ['first' => 'openid']], [['scopes', 'invalid_type']]],
            'two scopes refused'               => [['scopes' => ['openid', 'a b', '']], [['scopes.1', 'invalid_format'], ['scopes.2', 'required']]],
            'the most extra parameters'        => [['extra_parameters' => $mostParameters], $eachRefused],
            'a numbered parameter'             => [['extra_parameters' => ['login']], [['extra_parameters.0', 'not_allowed']]],
            'several, in the order named'      => [
                ['unknown' => 1, 'scopes' => ['email'], 'client_secret' => 'shh', 'issuer' => 'http://idp.example.com'],
                [['issuer', 'not_https'], ['client_secret', 'reserved'], ['scopes', 'openid_scope_required'], ['unknown', 'unknown']],
            ],
        ];
    }

    /**
     * Each rule reports its code at its setting's path, never the value.
     *
     * @param  array<array-key, mixed>  $values
     * @param  list<array{0: string, 1: string}>  $expected
     * @return void
     */
    #[DataProvider('provideViolations')]
    public function testReportsEachViolationAtItsSetting(array $values, array $expected): void
    {
        $settings = OidcSettings::fromArray($values);

        self::assertSame($expected, self::violationsOf($settings));
        self::assertFalse($settings->isComplete());
    }

    /**
     * Rows of `[name]`: each authorisation parameter the flow controls.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReservedParameters(): iterable
    {
        $names = [
            'response_type',
            'response_mode',
            'client_id',
            'redirect_uri',
            'scope',
            'state',
            'nonce',
            'code_challenge',
            'code_challenge_method',
            'request',
            'request_uri',
        ];

        foreach ($names as $name) {
            yield $name => [$name];
        }
    }

    /**
     * A parameter the flow controls can never be set, in any case (SSO-2.4).
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideReservedParameters')]
    public function testNeverSetsAParameterTheFlowControls(string $name): void
    {
        self::assertContains($name, OidcSettings::RESERVED_PARAMETERS);

        foreach ([$name, strtoupper($name), ucfirst($name)] as $spelling) {
            self::assertSame([['extra_parameters.' . $spelling, 'reserved']], self::violationsOf(OidcSettings::fromArray(['extra_parameters' => [$spelling => 'x']])));
        }
    }

    /**
     * Complete once valid and naming the issuer, the authorisation, token and
     * JWKS endpoints, and the client id.
     *
     * @return void
     */
    public function testIsCompleteWithTheIssuerEndpointsAndClientId(): void
    {
        self::assertTrue(OidcSettings::fromArray(self::COMPLETE)->isComplete());
        self::assertFalse(OidcSettings::fromArray([])->isComplete());

        foreach (array_keys(self::COMPLETE) as $name) {
            self::assertFalse(OidcSettings::fromArray(array_diff_key(self::COMPLETE, [$name => true]))->isComplete(), $name);
        }

        self::assertFalse(OidcSettings::fromArray(self::COMPLETE + ['scopes' => ['email']])->isComplete());
    }

    /**
     * The classification is `OidcSetting`'s: each setting's operation, the
     * subject settings and the client secret.
     *
     * @return void
     */
    public function testTakesItsClassificationFromTheSettingEnum(): void
    {
        foreach (OidcSetting::cases() as $setting) {
            self::assertSame($setting->freshness(), OidcSettings::freshnessFor($setting->value), $setting->value);
        }

        self::assertNull(OidcSettings::freshnessFor('idp_entity_id'));
        self::assertSame(OidcSetting::subjectNames(), OidcSettings::subjectNames());
        self::assertSame(['issuer', 'client_id'], OidcSettings::subjectNames());
        self::assertSame(OidcSetting::secretNames(), OidcSettings::secretNames());
        self::assertSame(['client_secret'], OidcSettings::secretNames());
        self::assertArrayNotHasKey('client_secret', OidcSettings::fromArray(['client_secret' => 'shh'])->toArray());
    }

    /**
     * Each violation as `[setting, code]`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings  $settings
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(OidcSettings $settings): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $settings->violations());
    }
}
