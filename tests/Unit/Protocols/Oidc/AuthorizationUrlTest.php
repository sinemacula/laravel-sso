<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Protocols\Oidc\AuthorizationUrl;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\TreatsWarningsAsErrors;
use Tests\Fixtures\Protocols\IdentifiedConnection;

/**
 * Unit tests for the URL of an OIDC authorisation code request (SSO-5.4,
 * SSO-5.10, SSO-2.4): the exact string for each purpose; `max_age` at 0, at a
 * configured value and absent; `prompt=login` winning for a reauthentication;
 * extra parameters in their stored order, never one the flow controls, in any
 * case; an endpoint's own query kept, or the request refused when it names a
 * parameter the request sets; and RFC 3986 encoding. A start without a nonce or
 * a PKCE verifier is the pipeline's bug.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationUrl::class)]
final class AuthorizationUrlTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var string The connection's authorisation endpoint. */
    private const string ENDPOINT = 'https://op.example.test/authorize';

    /** @var string The connection's callback. */
    private const string CALLBACK = 'https://api.example.com/auth/sso/connections/c1/callback';

    /** @var string The PKCE verifier sent, whose challenge has both characters base64url replaces. */
    private const string VERIFIER = 'verifier-h';

    /** @var string What every request sends before its `max_age`, `prompt` and extra parameters. */
    private const string QUERY = 'response_type=code'
        . '&client_id=client-1'
        . '&redirect_uri=https%3A%2F%2Fapi.example.com%2Fauth%2Fsso%2Fconnections%2Fc1%2Fcallback'
        . '&scope=openid%20email%20profile'
        . '&state=the-state'
        . '&nonce=the-nonce'
        . '&code_challenge=tVEoG_h-ykFXVOswYJ0K41ihO_I7oRNIQlnQ4veUvA4'
        . '&code_challenge_method=S256';

    /**
     * Rows of `[purpose, what it adds to the query]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 1: string}>
     */
    public static function providePurposes(): iterable
    {
        yield from [
            'a sign in'          => [Purpose::SIGN_IN, ''],
            'a link'             => [Purpose::LINK, ''],
            'a reauthentication' => [Purpose::REAUTHENTICATE, '&max_age=0&prompt=login'],
        ];
    }

    /**
     * Each purpose's URL is exactly this string: only a reauthentication forces
     * fresh authentication.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $added
     * @return void
     */
    #[DataProvider('providePurposes')]
    public function testEachPurposesUrlIsExact(Purpose $purpose, string $added): void
    {
        self::assertSame(self::ENDPOINT . '?' . self::QUERY . $added, self::urlFor([], $purpose));
    }

    /**
     * Rows of `[max_age, purpose, what it adds to the query]`: at its bounds,
     * at a value, absent, and overridden for a reauthentication.
     *
     * @return iterable<string, array{0: ?int, 1: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 2: string}>
     */
    public static function provideMaxAges(): iterable
    {
        yield from [
            'absent'                            => [null, Purpose::SIGN_IN, ''],
            'at zero'                           => [0, Purpose::SIGN_IN, '&max_age=0'],
            'at one'                            => [1, Purpose::SIGN_IN, '&max_age=1'],
            'at a value'                        => [3600, Purpose::SIGN_IN, '&max_age=3600'],
            'at a week'                         => [604800, Purpose::SIGN_IN, '&max_age=604800'],
            'for a link'                        => [3600, Purpose::LINK, '&max_age=3600'],
            'overridden for a reauthentication' => [3600, Purpose::REAUTHENTICATE, '&max_age=0&prompt=login'],
        ];
    }

    /**
     * `max_age` is sent as the connection configures it, as `0` too, not at all
     * when it has none, and `0` for a reauthentication whatever it has.
     *
     * @param  ?int  $maxAge
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $added
     * @return void
     */
    #[DataProvider('provideMaxAges')]
    public function testMaxAgeIsSentAsConfigured(?int $maxAge, Purpose $purpose, string $added): void
    {
        self::assertSame(self::ENDPOINT . '?' . self::QUERY . $added, self::urlFor(['max_age' => $maxAge], $purpose));
    }

    /**
     * An extra `prompt` is sent for a sign in, after `max_age`, and left out
     * for a reauthentication, whose `prompt=login` wins, the other extra
     * parameters kept.
     *
     * @return void
     */
    public function testPromptLoginWinsForAReauthentication(): void
    {
        $settings = ['max_age' => 60, 'extra_parameters' => ['prompt' => 'consent', 'login_hint' => 'kept']];

        self::assertSame(self::ENDPOINT . '?' . self::QUERY . '&max_age=60&prompt=consent&login_hint=kept', self::urlFor($settings));
        self::assertSame(self::ENDPOINT . '?' . self::QUERY . '&max_age=0&prompt=login&login_hint=kept', self::urlFor($settings, Purpose::REAUTHENTICATE));
    }

    /**
     * Extra parameters are sent last, in their stored order, whatever it is.
     *
     * @return void
     */
    public function testExtraParametersAreSentInTheirStoredOrder(): void
    {
        $url = self::urlFor(['extra_parameters' => ['ui_locales' => 'en-GB', 'acr_values' => 'mfa', 'hd' => 'example.com', 'display' => 'page']]);

        self::assertSame(self::ENDPOINT . '?' . self::QUERY . '&ui_locales=en-GB&acr_values=mfa&hd=example.com&display=page', $url);

        $reversed = self::urlFor(['extra_parameters' => ['display' => 'page', 'hd' => 'example.com', 'acr_values' => 'mfa', 'ui_locales' => 'en-GB']]);

        self::assertSame(self::ENDPOINT . '?' . self::QUERY . '&display=page&hd=example.com&acr_values=mfa&ui_locales=en-GB', $reversed);
    }

    /**
     * Rows of `[name]`: every parameter the flow controls, as listed and in
     * another case.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReservedNames(): iterable
    {
        foreach (OidcSettings::RESERVED_PARAMETERS as $name) {
            yield $name => [$name];
            yield strtoupper($name) => [strtoupper($name)];
            yield ucfirst($name) => [ucfirst($name)];
        }
    }

    /**
     * An extra parameter the settings would have refused can never set one the
     * flow controls, in any case: it is left out, and the others are sent.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideReservedNames')]
    public function testAnExtraParameterNeverSetsOneTheFlowControls(string $name): void
    {
        $url = self::urlFor(['extra_parameters' => ['login_hint' => 'before', $name => 'evil', 'display' => 'after']]);

        self::assertSame(self::ENDPOINT . '?' . self::QUERY . '&login_hint=before&display=after', $url);
    }

    /**
     * An extra parameter whose name the request already sets is left out in any
     * case: `prompt` and `max_age` for a reauthentication, and `max_age` when
     * the connection configures one.
     *
     * @return void
     */
    public function testAnExtraParameterNeverRepeatsOneTheRequestSets(): void
    {
        $extras = ['PROMPT' => 'none', 'Max_Age' => '9', 'max_age' => '9', 'hd' => 'kept'];

        self::assertSame(self::ENDPOINT . '?' . self::QUERY . '&max_age=0&prompt=login&hd=kept', self::urlFor(['extra_parameters' => $extras], Purpose::REAUTHENTICATE));

        unset($extras['PROMPT']);

        self::assertSame(self::ENDPOINT . '?' . self::QUERY . '&max_age=60&hd=kept', self::urlFor(['max_age' => 60, 'extra_parameters' => $extras]));
    }

    /**
     * An extra parameter that is not a string under a name is left out, never
     * encoded into a parameter of another shape.
     *
     * @return void
     */
    public function testAnExtraParameterThatIsNotAStringIsLeftOut(): void
    {
        $url = self::urlFor(['extra_parameters' => ['login_hint' => 42, 'display' => ['page'], 'ui_locales' => null, 'hd' => 'kept', 'acr_values' => true, 0 => 'listed']]);

        self::assertSame(self::ENDPOINT . '?' . self::QUERY . '&hd=kept', $url);
    }

    /**
     * Rows of `[endpoint, what joins the request's query]`: one that has a
     * query already, and one that ends with what joins a query.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEndpointQueries(): iterable
    {
        yield from [
            'with a query'                        => ['https://op.example.test/authorize?tenant=acme', '&'],
            'with two parameters'                 => ['https://op.example.test/authorize?tenant=acme&p=b2c_1_sign_in', '&'],
            'ending with a question mark'         => ['https://op.example.test/authorize?', ''],
            'ending with an ampersand'            => ['https://op.example.test/authorize?tenant=acme&', ''],
            'whose value names one'               => ['https://op.example.test/authorize?tenant=state', '&'],
            'with an empty parameter'             => ['https://op.example.test/authorize?tenant=acme&&p=1', '&'],
            'with a name and no value'            => ['https://op.example.test/authorize?beta', '&'],
            'with a name that only begins as one' => ['https://op.example.test/authorize?state_hint=1&nonces=2', '&'],
        ];
    }

    /**
     * An endpoint's own query is kept as it is, and the request's appended.
     *
     * @param  string  $endpoint
     * @param  string  $separator
     * @return void
     */
    #[DataProvider('provideEndpointQueries')]
    public function testAnEndpointsOwnQueryIsKept(string $endpoint, string $separator): void
    {
        self::assertSame($endpoint . $separator . self::QUERY, self::urlFor([], Purpose::SIGN_IN, $endpoint));
    }

    /**
     * Rows of `[query, settings, purpose]`: an endpoint's query that names a
     * parameter the request sets, however it writes the name, or one the flow
     * controls and never sets.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>, 2: \SineMacula\Laravel\Sso\Flows\Enums\Purpose}>
     */
    public static function provideConflictingQueries(): iterable
    {
        yield from [
            'the state'                      => ['state=x', [], Purpose::SIGN_IN],
            'the state, after another'       => ['tenant=acme&state=x', [], Purpose::SIGN_IN],
            'the state, before another'      => ['state=x&tenant=acme', [], Purpose::SIGN_IN],
            'the state in upper case'        => ['STATE=x', [], Purpose::SIGN_IN],
            'the state percent-encoded'      => ['%73tate=x', [], Purpose::SIGN_IN],
            'the state with no value'        => ['state', [], Purpose::SIGN_IN],
            'the state after a second mark'  => ['a=1?b&state=x', [], Purpose::SIGN_IN],
            'the client id in another case'  => ['Client_Id=x', [], Purpose::SIGN_IN],
            'the redirect URI'               => ['redirect_uri=https%3A%2F%2Fevil.example', [], Purpose::SIGN_IN],
            'the response type'              => ['response_type=token', [], Purpose::SIGN_IN],
            'the scope'                      => ['scope=admin', [], Purpose::SIGN_IN],
            'the nonce'                      => ['nonce=x', [], Purpose::SIGN_IN],
            'the challenge'                  => ['code_challenge=x', [], Purpose::SIGN_IN],
            'the challenge method'           => ['code_challenge_method=plain', [], Purpose::SIGN_IN],
            'a response mode it never sends' => ['response_mode=fragment', [], Purpose::SIGN_IN],
            'a request it never sends'       => ['request=x', [], Purpose::SIGN_IN],
            'a request URI it never sends'   => ['request_uri=x', [], Purpose::SIGN_IN],
            'the configured max age'         => ['max_age=1', ['max_age' => 60], Purpose::SIGN_IN],
            'a reauthentication\'s max age'  => ['max_age=1', [], Purpose::REAUTHENTICATE],
            'a reauthentication\'s prompt'   => ['prompt=none', [], Purpose::REAUTHENTICATE],
            'an extra parameter'             => ['LOGIN_HINT=x', ['extra_parameters' => ['login_hint' => 'a']], Purpose::SIGN_IN],
            'an extra parameter in its case' => ['prompt=none', ['extra_parameters' => ['Prompt' => 'consent']], Purpose::SIGN_IN],
        ];
    }

    /**
     * An endpoint whose own query names a parameter the request sets, in any
     * case or encoding, or one the flow controls, gives no URL: nothing is
     * overridden or sent twice.
     *
     * @param  string  $query
     * @param  array<string, mixed>  $settings
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('provideConflictingQueries')]
    public function testAnEndpointQueryNamingAParameterGivesNoUrl(string $query, array $settings, Purpose $purpose): void
    {
        self::assertNull(self::urlFor($settings, $purpose, self::ENDPOINT . '?' . $query));
    }

    /**
     * What the request does not send is free for the endpoint's own query:
     * `max_age` and `prompt` with neither configured, and an extra parameter
     * the connection does not set.
     *
     * @return void
     */
    public function testAnEndpointQueryMayNameWhatTheRequestDoesNotSend(): void
    {
        $endpoint = self::ENDPOINT . '?max_age=1&prompt=none&login_hint=x';

        self::assertSame($endpoint . '&' . self::QUERY, self::urlFor([], Purpose::SIGN_IN, $endpoint));
    }

    /**
     * An endpoint with a fragment gives no URL, whether or not it has a query:
     * a query appended after a fragment would never reach the provider.
     *
     * @return void
     */
    public function testAnEndpointWithAFragmentGivesNoUrl(): void
    {
        self::assertNull(self::urlFor([], Purpose::SIGN_IN, self::ENDPOINT . '#fragment'));
        self::assertNull(self::urlFor([], Purpose::SIGN_IN, self::ENDPOINT . '?tenant=acme#fragment'));
    }

    /**
     * Every value is encoded per RFC 3986: a space as `%20`, never `+`, the
     * reserved characters percent-encoded, and the unreserved ones left alone.
     *
     * @return void
     */
    public function testValuesAreEncodedPerRfc3986(): void
    {
        $url = self::urlFor([
            'client_id'        => 'client 1/ä',
            'scopes'           => ['profile', 'openid', 'urn:example:read'],
            'extra_parameters' => ['login_hint' => 'a b+c@example.com/x?y=z&w#v~._-'],
        ]);

        self::assertSame(self::ENDPOINT . '?response_type=code'
            . '&client_id=client%201%2F%C3%A4'
            . '&redirect_uri=https%3A%2F%2Fapi.example.com%2Fauth%2Fsso%2Fconnections%2Fc1%2Fcallback'
            . '&scope=profile%20openid%20urn%3Aexample%3Aread'
            . '&state=the-state'
            . '&nonce=the-nonce'
            . '&code_challenge=tVEoG_h-ykFXVOswYJ0K41ihO_I7oRNIQlnQ4veUvA4'
            . '&code_challenge_method=S256'
            . '&login_hint=a%20b%2Bc%40example.com%2Fx%3Fy%3Dz%26w%23v~._-', $url);
    }

    /**
     * The scopes are joined by single spaces in their stored order, and the
     * redirect URI is sent exactly as given.
     *
     * @return void
     */
    public function testScopesAndTheRedirectUriAreSentAsTheyAre(): void
    {
        $url = AuthorizationUrl::build(
            self::ENDPOINT,
            self::options(['scopes' => ['email', 'openid']]),
            self::request(Purpose::SIGN_IN),
            'http://127.0.0.1:8080/Call Back/?a=b',
        );

        parse_str((string) parse_url((string) $url, PHP_URL_QUERY), $query);

        self::assertSame('email openid', $query['scope'] ?? null);
        self::assertSame('http://127.0.0.1:8080/Call Back/?a=b', $query['redirect_uri'] ?? null);
    }

    /**
     * The challenge is RFC 7636's own example of S256.
     *
     * @return void
     */
    public function testTheChallengeIsRfc7636s(): void
    {
        $request = new StartRequest(
            Purpose::SIGN_IN,
            'web',
            self::reference(),
            new Secret('the-state'),
            new Secret('the-nonce'),
            new Secret('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
        );

        $url = (string) AuthorizationUrl::build(self::ENDPOINT, self::options([]), $request, self::CALLBACK);

        self::assertStringEndsWith('&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256', $url);
    }

    /**
     * Rows of `[purpose]`: each purpose a flow starts for.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose}>
     */
    public static function provideEachPurpose(): iterable
    {
        yield from [
            'a sign in'          => [Purpose::SIGN_IN],
            'a link'             => [Purpose::LINK],
            'a reauthentication' => [Purpose::REAUTHENTICATE],
        ];
    }

    /**
     * The request carries neither `response_mode` nor `request` nor
     * `request_uri`, for any purpose.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('provideEachPurpose')]
    public function testNoResponseModeOrRequestObjectIsEverSent(Purpose $purpose): void
    {
        $url = (string) self::urlFor([], $purpose);

        foreach (['response_mode', 'request=', 'request_uri'] as $name) {
            self::assertStringNotContainsString($name, $url);
        }
    }

    /**
     * Rows of `[nonce, verifier, message]`: what a start missing one is told.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: string}>
     */
    public static function provideMissingValues(): iterable
    {
        yield from [
            'no nonce'    => [null, self::VERIFIER, 'An OIDC start is given a nonce; the start pipeline makes one for every start.'],
            'no verifier' => ['the-nonce', null, 'An OIDC start is given a PKCE verifier; the start pipeline makes one for every start.'],
        ];
    }

    /**
     * A start without a nonce or a PKCE verifier is the pipeline's bug, and the
     * message names no value.
     *
     * @param  ?string  $nonce
     * @param  ?string  $verifier
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMissingValues')]
    public function testAStartWithoutItsValuesIsALogicException(?string $nonce, ?string $verifier, string $message): void
    {
        $request = new StartRequest(
            Purpose::SIGN_IN,
            'web',
            self::reference(),
            new Secret('the-state'),
            $nonce    === null ? null : new Secret($nonce),
            $verifier === null ? null : new Secret($verifier),
        );

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage($message);

        AuthorizationUrl::build(self::ENDPOINT, self::options([]), $request, self::CALLBACK);
    }

    /**
     * The URL for a request of the purpose, through a connection of client
     * `client-1` with the settings laid over that, to the endpoint.
     *
     * @param  array<string, mixed>  $settings
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $endpoint
     * @return ?string
     */
    private static function urlFor(array $settings, Purpose $purpose = Purpose::SIGN_IN, string $endpoint = self::ENDPOINT): ?string
    {
        return AuthorizationUrl::build($endpoint, self::options($settings), self::request($purpose), self::CALLBACK);
    }

    /**
     * The options of a connection of client `client-1` with the settings laid
     * over that.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions
     */
    private static function options(array $settings): OidcOptions
    {
        return OidcOptions::of(new IdentifiedConnection('c1', settings: [...['client_id' => 'client-1'], ...$settings]));
    }

    /**
     * A request of the purpose with fixed protocol values.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Sso\Protocols\StartRequest
     */
    private static function request(Purpose $purpose): StartRequest
    {
        return new StartRequest($purpose, 'web', self::reference(), new Secret('the-state'), new Secret('the-nonce'), new Secret(self::VERIFIER));
    }

    /**
     * A public reference, never sent.
     *
     * @return \SineMacula\Laravel\Sso\Flows\RequestReference
     */
    private static function reference(): RequestReference
    {
        return RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456');
    }
}
