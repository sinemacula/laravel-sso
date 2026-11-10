<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Random\RandomException;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Protocols\Saml2\AuthnRequests;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AuthnRequestWriter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Start;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the SAML `AuthnRequest` and its bindings (SSO-5.3,
 * SSO-5.10, SSO-5.2, SSO-9.8), through the driver's start, each message decoded
 * (inflated for HTTP-Redirect) and parsed with DOM: every field, the `ID`'s
 * shape and uniqueness, `ForceAuthn` for `force_authn` and for a
 * `reauthenticate`, the requested context compared exactly, the NameID policy
 * of each format, the query's order, each binding's signature verified with
 * OpenSSL for each algorithm, `RelayState` as the state and its limit, a single
 * sign-on URL with a query, the refusal with no current signing key, and
 * nothing logged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthnRequests::class)]
#[CoversClass(AuthnRequestWriter::class)]
#[CoversClass(OutgoingRequest::class)]
final class AuthnRequestsTest extends TestCase
{
    use CapturesLogs, UsesConnections;

    /** @var string The identity provider's single sign-on URL. */
    private const string SSO_URL = 'https://idp.example.com/saml/sso';

    /** @var string The base URL the endpoints are built from. */
    private const string BASE_URL = 'https://api.example.com';

    /** @var string The `RelayState` a start is given: 43 base64url characters. */
    private const string STATE = 'Rs7-state_0123456789abcdefghijklmnopqrstuvw';

    /** @var string The HTTP-POST binding. */
    private const string HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    /** @var string The SAML protocol namespace. */
    private const string NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /** @var string The SAML assertion namespace. */
    private const string NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** @var string The XML signature namespace. */
    private const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /** @var string Exclusive canonicalisation without comments. */
    private const string EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /** @var string The pattern of a request id: `_` and 64 lower-case hex digits. */
    private const string ID_PATTERN = '/^_[0-9a-f]{64}$/D';

    /** @var array<string, array{0: string, 1: int, 2: string, 3: string}> Each allowed algorithm: its URI, OpenSSL hash, digest URI and PHP hash. */
    private const array ALGORITHMS = [
        'rsa-sha256' => ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', OPENSSL_ALGO_SHA256, 'http://www.w3.org/2001/04/xmlenc#sha256', 'sha256'],
        'rsa-sha384' => ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', OPENSSL_ALGO_SHA384, 'http://www.w3.org/2001/04/xmldsig-more#sha384', 'sha384'],
        'rsa-sha512' => ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', OPENSSL_ALGO_SHA512, 'http://www.w3.org/2001/04/xmlenc#sha512', 'sha512'],
    ];

    /** @var ?array{0: string, 1: string} The service provider's signing key and certificate, made once. */
    private static ?array $spKeys = null;

    /**
     * Bind a fixed clock, switch SAML on, configure the endpoints and create
     * the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        config()->set('sso.features.saml2', true);
        config()->set('sso.endpoints.base_url', self::BASE_URL);

        $this->usePackageTables();
    }

    /**
     * An unsigned HTTP-Redirect request carries every field, and its query only
     * `SAMLRequest` and `RelayState`, in that order.
     *
     * @return void
     */
    public function testAnUnsignedRedirectCarriesEveryField(): void
    {
        $connection = $this->saml();
        $start      = $this->start($connection);
        $navigation = self::navigationOf($start);
        $query      = self::queryOf($navigation->url());

        self::assertTrue($navigation->isRedirect());
        self::assertStringStartsWith(self::SSO_URL . '?SAMLRequest=', $navigation->url());
        self::assertSame(['SAMLRequest', 'RelayState'], array_column($query, 0));
        self::assertSame(self::STATE, $query[1][1]);

        $root = self::rootOf((string) gzinflate((string) base64_decode($query[0][1], true)));

        $this->assertEveryField($connection, $root, $start);
        self::assertSame(['Issuer', 'NameIDPolicy'], self::children($root));
    }

    /**
     * An unsigned HTTP-POST request carries every field, posted as
     * `SAMLRequest` and `RelayState` to the single sign-on URL.
     *
     * @return void
     */
    public function testAnUnsignedPostCarriesEveryField(): void
    {
        $connection = $this->saml(['sso_binding' => 'http_post']);
        $start      = $this->start($connection);
        $navigation = self::navigationOf($start);
        $fields     = $navigation->fields();

        self::assertTrue($navigation->isPost());
        self::assertSame(self::SSO_URL, $navigation->url());
        self::assertSame(['SAMLRequest', 'RelayState'], array_keys($fields));
        self::assertSame(self::STATE, $fields['RelayState']);

        $root = self::rootOf((string) base64_decode($fields['SAMLRequest'], true));

        $this->assertEveryField($connection, $root, $start);
        self::assertSame(['Issuer', 'NameIDPolicy'], self::children($root));
    }

    /**
     * Each start's `ID` is `_` and 64 lower-case hex digits, and no two are the
     * same.
     *
     * @return void
     */
    public function testEachRequestHasAFreshIdOfItsShape(): void
    {
        $connection = $this->saml();
        $ids        = [];

        for ($index = 0; $index < 5; $index++) {
            $start = $this->start($connection);

            self::assertMatchesRegularExpression(self::ID_PATTERN, (string) $start->samlRequestId);
            self::assertSame(65, strlen((string) $start->samlRequestId));
            self::assertSame($start->samlRequestId, self::redirectRoot($start)->getAttribute('ID'));

            $ids[] = $start->samlRequestId;
        }

        self::assertCount(5, array_unique($ids));
    }

    /**
     * Rows of `[forceAuthn, purpose, forced]`: the connection's switch, the
     * flow's purpose, and whether the request forces authentication.
     *
     * @return iterable<string, array{0: bool, 1: \SineMacula\Laravel\Sso\Flows\Enums\Purpose, 2: bool}>
     */
    public static function provideForceAuthn(): iterable
    {
        yield from [
            'sign in'                         => [false, Purpose::SIGN_IN, false],
            'link'                            => [false, Purpose::LINK, false],
            'reauthenticate'                  => [false, Purpose::REAUTHENTICATE, true],
            'sign in with force_authn'        => [true, Purpose::SIGN_IN, true],
            'link with force_authn'           => [true, Purpose::LINK, true],
            'reauthenticate with force_authn' => [true, Purpose::REAUTHENTICATE, true],
        ];
    }

    /**
     * `ForceAuthn="true"` when the connection forces authentication or the flow
     * is a `reauthenticate`, and absent otherwise, by either binding.
     *
     * @param  bool  $forceAuthn
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  bool  $forced
     * @return void
     */
    #[DataProvider('provideForceAuthn')]
    public function testForceAuthnFollowsTheSwitchAndReauthentication(bool $forceAuthn, Purpose $purpose, bool $forced): void
    {
        $redirect = self::redirectRoot($this->start($this->saml(['force_authn' => $forceAuthn]), $purpose));
        $post     = self::postRoot($this->start($this->saml(['force_authn' => $forceAuthn, 'sso_binding' => 'http_post']), $purpose));

        foreach ([$redirect, $post] as $root) {
            self::assertSame($forced, $root->hasAttribute('ForceAuthn'));
            self::assertSame($forced ? 'true' : '', $root->getAttribute('ForceAuthn'));
            self::assertFalse($root->hasAttribute('IsPassive'));
        }
    }

    /**
     * The requested context lists the connection's classes in order, compared
     * exactly, after the NameID policy.
     *
     * @return void
     */
    public function testTheRequestedContextIsComparedExactly(): void
    {
        $classes = ['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', 'https://refeds.org/profile/mfa'];
        $root    = self::redirectRoot($this->start($this->saml(['requested_authn_context' => $classes])));
        $context = self::only($root, self::NS_SAMLP, 'RequestedAuthnContext');
        $refs    = array_map(static fn (\DOMElement $ref): string => $ref->textContent, self::elements($context, self::NS_SAML, 'AuthnContextClassRef'));

        self::assertSame(['Issuer', 'NameIDPolicy', 'RequestedAuthnContext'], self::children($root));
        self::assertSame(['Comparison' => 'exact'], self::attributes($context));
        self::assertSame($classes, $refs);
        self::assertSame(['AuthnContextClassRef', 'AuthnContextClassRef'], self::children($context));
    }

    /**
     * Rows of `[format, uri]`: each NameID format a connection may name.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideNameIdFormats(): iterable
    {
        yield from [
            'persistent'  => ['persistent', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'],
            'email'       => ['email', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
            'unspecified' => ['unspecified', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'],
        ];
    }

    /**
     * The NameID policy names the connection's format, allowing creation.
     *
     * @param  string  $format
     * @param  string  $uri
     * @return void
     */
    #[DataProvider('provideNameIdFormats')]
    public function testTheNameIdPolicyNamesTheConnectionsFormat(string $format, string $uri): void
    {
        $root = self::redirectRoot($this->start($this->saml(['name_id_format' => $format])));

        self::assertSame(['AllowCreate' => 'true', 'Format' => $uri], self::attributes(self::only($root, self::NS_SAMLP, 'NameIDPolicy')));
    }

    /**
     * Rows of `[algorithm]`: each signature algorithm a connection may allow.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAlgorithms(): iterable
    {
        foreach (array_keys(self::ALGORITHMS) as $name) {
            yield $name => [$name];
        }
    }

    /**
     * A signed HTTP-Redirect request carries `SAMLRequest`, `RelayState`,
     * `SigAlg` and `Signature` in that order, the signature verifies over the
     * exact bytes of the first three with the first algorithm allowed, and the
     * XML carries no signature.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideAlgorithms')]
    public function testASignedRedirectVerifiesOverTheExactQuery(string $name): void
    {
        [$uri, $hash] = self::ALGORITHMS[$name];

        $connection = $this->saml(['sign_authn_requests' => true, 'signature_algorithms' => self::algorithmsFirst($uri)]);

        $this->signingKey($connection);

        $url   = self::navigationOf($this->start($connection))->url();
        $query = self::queryOf($url);
        $raw   = (string) parse_url($url, PHP_URL_QUERY);
        $cut   = strpos($raw, '&Signature=');

        self::assertSame(['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'], array_column($query, 0));
        self::assertSame($uri, $query[2][1]);
        self::assertIsInt($cut);
        self::assertSame(sprintf('SAMLRequest=%s&RelayState=%s&SigAlg=%s', rawurlencode($query[0][1]), self::STATE, rawurlencode($uri)), substr($raw, 0, $cut));
        self::assertSame(1, openssl_verify(substr($raw, 0, $cut), (string) base64_decode($query[3][1], true), self::keys()[1], $hash));
        self::assertSame(0, openssl_verify(substr($raw, 0, $cut) . 'x', (string) base64_decode($query[3][1], true), self::keys()[1], $hash));

        $root = self::rootOf((string) gzinflate((string) base64_decode($query[0][1], true)));

        self::assertSame(0, $root->getElementsByTagNameNS(self::NS_DS, 'Signature')->length);
    }

    /**
     * A signed HTTP-POST request carries an enveloped signature right after its
     * `Issuer`, referencing its `ID` with only the enveloped and exclusive
     * canonicalisation transforms, with the algorithm's digest, and both the
     * digest and the signature verify with OpenSSL.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideAlgorithms')]
    public function testASignedPostCarriesAVerifyingEnvelopedSignature(string $name): void
    {
        [$uri, $hash, $digestUri, $digestHash] = self::ALGORITHMS[$name];

        $connection = $this->saml(['sign_authn_requests' => true, 'sso_binding' => 'http_post', 'signature_algorithms' => self::algorithmsFirst($uri)]);

        $this->signingKey($connection);

        $start      = $this->start($connection);
        $root       = self::postRoot($start);
        $signature  = self::only($root, self::NS_DS, 'Signature');
        $info       = self::only($signature, self::NS_DS, 'SignedInfo');
        $reference  = self::only($info, self::NS_DS, 'Reference');
        $value      = (string) base64_decode(self::only($signature, self::NS_DS, 'SignatureValue')->textContent, true);
        $digest     = self::only($reference, self::NS_DS, 'DigestValue')->textContent;
        $transforms = self::elements(self::only($reference, self::NS_DS, 'Transforms'), self::NS_DS, 'Transform');
        $methods    = array_map(static fn (\DOMElement $method): string => $method->getAttribute('Algorithm'), $transforms);

        self::assertSame(['Issuer', 'Signature', 'NameIDPolicy'], self::children($root));
        self::assertSame(['SignedInfo', 'SignatureValue'], self::children($signature));
        self::assertSame(['CanonicalizationMethod', 'SignatureMethod', 'Reference'], self::children($info));
        self::assertSame(self::EXC_C14N, self::only($info, self::NS_DS, 'CanonicalizationMethod')->getAttribute('Algorithm'));
        self::assertSame($uri, self::only($info, self::NS_DS, 'SignatureMethod')->getAttribute('Algorithm'));
        self::assertSame('#' . $start->samlRequestId, $reference->getAttribute('URI'));
        self::assertSame([self::NS_DS . 'enveloped-signature', self::EXC_C14N], $methods);
        self::assertSame($digestUri, self::only($reference, self::NS_DS, 'DigestMethod')->getAttribute('Algorithm'));
        self::assertSame(1, openssl_verify((string) $info->C14N(true, false), $value, self::keys()[1], $hash));

        $root->removeChild($signature);

        self::assertSame($digest, base64_encode(hash($digestHash, (string) $root->C14N(true, false), true)));
    }

    /**
     * An unsigned request carries no signature in either binding, even with a
     * current signing key.
     *
     * @return void
     */
    public function testAnUnsignedRequestCarriesNoSignature(): void
    {
        $redirect = $this->saml();
        $post     = $this->saml(['sso_binding' => 'http_post']);

        $this->signingKey($redirect);
        $this->signingKey($post);

        $url = self::navigationOf($this->start($redirect))->url();

        self::assertSame(['SAMLRequest', 'RelayState'], array_column(self::queryOf($url), 0));
        self::assertStringNotContainsString('SigAlg', $url);
        self::assertSame(0, self::postRoot($this->start($post))->getElementsByTagNameNS(self::NS_DS, 'Signature')->length);
    }

    /**
     * Rows of `[ssoUrl, prefix]`: a single sign-on URL, and what the redirect
     * starts with.
     *
     * @return iterable<string, array{0: string, 1: non-empty-string}>
     */
    public static function provideSingleSignOnUrls(): iterable
    {
        yield from [
            'no query'            => ['https://idp.example.com/sso', 'https://idp.example.com/sso?SAMLRequest='],
            'a query'             => ['https://idp.example.com/sso?tenant=a', 'https://idp.example.com/sso?tenant=a&SAMLRequest='],
            'an empty query'      => ['https://idp.example.com/sso?', 'https://idp.example.com/sso?SAMLRequest='],
            'a query ending in &' => ['https://idp.example.com/sso?tenant=a&', 'https://idp.example.com/sso?tenant=a&SAMLRequest='],
        ];
    }

    /**
     * The query is appended after `?`, after `&` when the single sign-on URL
     * has a query, and directly when it ends with either; the destination is
     * the URL as configured.
     *
     * @param  string  $ssoUrl
     * @param  non-empty-string  $prefix
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideSingleSignOnUrls')]
    public function testTheQueryIsAppendedToTheSingleSignOnUrl(string $ssoUrl, string $prefix): void
    {
        $connection = $this->saml();
        $options    = self::samlOptions($ssoUrl);
        $start      = app(AuthnRequests::class)->start($connection, $options, self::request());
        $url        = self::navigationOf($start)->url();
        $query      = self::queryOf($url);
        $sent       = array_slice($query, -2);

        self::assertStringStartsWith($prefix, $url);
        self::assertSame(['SAMLRequest', 'RelayState'], array_column($sent, 0));
        self::assertSame($ssoUrl, self::rootOf((string) gzinflate((string) base64_decode($sent[0][1], true)))->getAttribute('Destination'));
    }

    /**
     * Rows of `[keys]`: the signing keys a connection that signs its requests
     * holds with no current one.
     *
     * @return iterable<string, array{0: list<\SineMacula\Laravel\Sso\Keys\Enums\KeyState>}>
     */
    public static function provideNoCurrentKey(): iterable
    {
        yield from [
            'no key'          => [[]],
            'only a next key' => [[KeyState::NEXT]],
        ];
    }

    /**
     * A connection that signs its requests with no current signing key is
     * refused with `connection_unavailable`, by either binding.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\Enums\KeyState>  $states
     * @return void
     */
    #[DataProvider('provideNoCurrentKey')]
    public function testNoCurrentSigningKeyIsUnavailable(array $states): void
    {
        foreach (['http_redirect', 'http_post'] as $binding) {

            $connection = $this->saml(['sign_authn_requests' => true, 'sso_binding' => $binding]);

            foreach ($states as $state) {
                $this->signingKey($connection, $state);
            }

            $start = $this->start($connection);

            self::assertTrue($start->isRefused());
            self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $start->reason);
            self::assertNull($start->navigation);
            self::assertNull($start->samlRequestId);
        }
    }

    /**
     * A connection with no single sign-on URL is refused with
     * `connection_unavailable`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNoSingleSignOnUrlIsUnavailable(): void
    {
        $start = app(AuthnRequests::class)->start($this->saml(), self::samlOptions(null), self::request());

        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $start->reason);
        self::assertNull($start->navigation);
    }

    /**
     * `RelayState` is the state given, up to 80 bytes; a longer one is a
     * `LogicException` naming none of it.
     *
     * @return void
     */
    public function testTheRelayStateIsTheStateUpToEightyBytes(): void
    {
        $connection = $this->saml();
        $longest    = str_repeat('a', 80);
        $start      = $this->start($connection, state: $longest);

        self::assertSame($longest, self::queryOf(self::navigationOf($start)->url())[1][1]);
        self::assertSame(80, AuthnRequests::MAX_RELAY_STATE_BYTES);

        try {
            $this->start($connection, state: str_repeat('b', 81));
            self::fail('A RelayState over 80 bytes was sent.');
        } catch (\LogicException $exception) {
            self::assertSame('A SAML RelayState is at most 80 bytes.', $exception->getMessage());
            self::assertStringNotContainsString('bbbb', $exception->getMessage());
        }
    }

    /**
     * Starting signed requests by either binding logs nothing: no state, no
     * message, no signature and no key.
     *
     * @return void
     */
    public function testNothingOfTheRequestIsLogged(): void
    {
        $this->captureLogs();

        $redirect = $this->saml(['sign_authn_requests' => true]);
        $post     = $this->saml(['sign_authn_requests' => true, 'sso_binding' => 'http_post']);

        $this->signingKey($redirect);
        $this->signingKey($post);

        $sent = [
            ...array_column(self::queryOf(self::navigationOf($this->start($redirect))->url()), 1),
            ...array_values(self::navigationOf($this->start($post))->fields()),
        ];

        self::assertSame([], $this->capturedLogRecords());
        $this->assertNothingLoggedContains(self::STATE, ...$sent);
    }

    /**
     * Assert the request carries every field of an unsigned start through the
     * connection, as the start answered it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \DOMElement  $root
     * @param  \SineMacula\Laravel\Sso\Protocols\Start  $start
     * @return void
     */
    private function assertEveryField(Connection $connection, \DOMElement $root, Start $start): void
    {
        $base = self::BASE_URL . '/auth/sso/connections/' . $connection->id;

        self::assertNotNull($start->samlRequestId);
        self::assertMatchesRegularExpression(self::ID_PATTERN, $start->samlRequestId);
        self::assertSame(['samlp', self::NS_SAMLP, 'AuthnRequest'], [$root->prefix, $root->namespaceURI, $root->localName]);
        self::assertSame([
            'AssertionConsumerServiceURL' => $base . '/assertions',
            'Destination'                 => self::SSO_URL,
            'ID'                          => $start->samlRequestId,
            'IssueInstant'                => '2026-11-01T09:30:00Z',
            'ProtocolBinding'             => self::HTTP_POST,
            'Version'                     => '2.0',
        ], self::attributes($root));

        $issuer = self::only($root, self::NS_SAML, 'Issuer');

        self::assertSame($base . '/metadata', $issuer->textContent);
        self::assertSame([], self::attributes($issuer));
        self::assertSame(
            ['AllowCreate' => 'true', 'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'],
            self::attributes(self::only($root, self::NS_SAMLP, 'NameIDPolicy')),
        );
        self::assertNull($start->expectedIssuer);
        self::assertFalse($start->issuerRequired);
    }

    /**
     * Start a request through the driver, a `sign_in` with the state unless
     * told otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $state
     * @return \SineMacula\Laravel\Sso\Protocols\Start
     *
     * @throws \LogicException
     */
    private function start(Connection $connection, Purpose $purpose = Purpose::SIGN_IN, string $state = self::STATE): Start
    {
        try {
            return app(Saml2Driver::class)->start($connection, self::request($purpose, $state));
        } catch (RandomException $exception) {
            throw new \LogicException('The system has no randomness.', 0, $exception);
        }
    }

    /**
     * A start request with the purpose and state.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $state
     * @return \SineMacula\Laravel\Sso\Protocols\StartRequest
     */
    private static function request(Purpose $purpose = Purpose::SIGN_IN, string $state = self::STATE): StartRequest
    {
        return new StartRequest($purpose, 'web', RequestReference::fromString('Sq8tVv3w0kLmNoPqRsTuVwXyZ0123456'), new Secret($state));
    }

    /**
     * A SAML connection with complete settings and the changes given.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $settings = []): Connection
    {
        return $this->makeConnection([
            'protocol' => 'saml2',
            'enabled'  => true,
            'settings' => [...['idp_entity_id' => 'https://idp.example.com/entity', 'sso_url' => self::SSO_URL], ...$settings],
        ]);
    }

    /**
     * Options with the single sign-on URL given and every other setting's
     * default, for a start asked of the requests directly.
     *
     * @param  ?string  $ssoUrl
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options
     */
    private static function samlOptions(?string $ssoUrl): Saml2Options
    {
        return new Saml2Options('https://idp.example.com/entity', $ssoUrl, 'http_redirect', 'name_id', null, 'persistent', [], [], null, null, null);
    }

    /**
     * Store the service provider's signing key for the connection, in the state
     * given, its private half encrypted as the key service would.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @return void
     */
    private function signingKey(Connection $connection, KeyState $state = KeyState::CURRENT): void
    {
        [$private, $certificate] = self::keys();

        $public  = openssl_pkey_get_public($certificate);
        $details = $public === false ? false : openssl_pkey_get_details($public);

        self::assertIsArray($details);

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::SP_SIGNING,
            'state'         => $state,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $certificate,
            'public_key'    => $details['key'],
            'private_key'   => app(SecretEncrypter::class)->encrypt($private),
            'fingerprint'   => (string) openssl_x509_fingerprint($certificate, 'sha256'),
        ])->save();
    }

    /**
     * The service provider's signing key and certificate, made once.
     *
     * @return array{0: string, 1: string}
     */
    private static function keys(): array
    {
        return self::$spKeys ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }

    /**
     * Every allowed algorithm, the one given first.
     *
     * @param  string  $first
     * @return list<string>
     */
    private static function algorithmsFirst(string $first): array
    {
        return array_values(array_unique([$first, ...array_column(self::ALGORITHMS, 0)]));
    }

    /**
     * The navigation of a started request.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Start  $start
     * @return \SineMacula\Laravel\Sso\Protocols\Navigation
     */
    private static function navigationOf(Start $start): Navigation
    {
        self::assertTrue($start->isNavigating());
        self::assertNotNull($start->navigation);

        return $start->navigation;
    }

    /**
     * The URL's query as `[name, decoded value]` pairs, in order.
     *
     * @param  string  $url
     * @return list<array{0: string, 1: string}>
     */
    private static function queryOf(string $url): array
    {
        $query = (string) parse_url($url, PHP_URL_QUERY);
        $pairs = [];

        foreach (explode('&', $query) as $pair) {

            if ($pair === '') {
                continue;
            }

            $parts   = explode('=', $pair, 2);
            $pairs[] = [$parts[0], rawurldecode($parts[1] ?? '')];
        }

        return $pairs;
    }

    /**
     * The root of the request a redirect sent, inflated and parsed.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Start  $start
     * @return \DOMElement
     */
    private static function redirectRoot(Start $start): \DOMElement
    {
        $message = self::queryOf(self::navigationOf($start)->url())[0];

        self::assertSame('SAMLRequest', $message[0]);

        return self::rootOf((string) gzinflate((string) base64_decode($message[1], true)));
    }

    /**
     * The root of the request a post sent, decoded and parsed.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Start  $start
     * @return \DOMElement
     */
    private static function postRoot(Start $start): \DOMElement
    {
        return self::rootOf((string) base64_decode(self::navigationOf($start)->fields()['SAMLRequest'], true));
    }

    /**
     * The XML's root element, parsed with no network.
     *
     * @param  string  $xml
     * @return \DOMElement
     */
    private static function rootOf(string $xml): \DOMElement
    {
        $document = new \DOMDocument;

        self::assertTrue($document->loadXML($xml, LIBXML_NONET));
        self::assertNotNull($document->documentElement);

        return $document->documentElement;
    }

    /**
     * The element's one child of the namespace and name.
     *
     * @param  \DOMElement  $parent
     * @param  string  $namespace
     * @param  string  $name
     * @return \DOMElement
     */
    private static function only(\DOMElement $parent, string $namespace, string $name): \DOMElement
    {
        $children = self::elements($parent, $namespace, $name);

        self::assertCount(1, $children);

        return $children[0];
    }

    /**
     * The element's children of the namespace and name, in order.
     *
     * @param  \DOMElement  $parent
     * @param  string  $namespace
     * @param  string  $name
     * @return list<\DOMElement>
     */
    private static function elements(\DOMElement $parent, string $namespace, string $name): array
    {
        $found = [];

        foreach ($parent->childNodes as $child) {

            $matches = $child instanceof \DOMElement && $child->namespaceURI === $namespace && $child->localName === $name;

            if (!$matches) {
                continue;
            }

            $found[] = $child;
        }

        return $found;
    }

    /**
     * The local names of the element's child elements, in order.
     *
     * @param  \DOMElement  $parent
     * @return list<string>
     */
    private static function children(\DOMElement $parent): array
    {
        $names = [];

        foreach ($parent->childNodes as $child) {

            if (!$child instanceof \DOMElement) {
                continue;
            }

            $names[] = (string) $child->localName;
        }

        return $names;
    }

    /**
     * The element's attributes but namespace declarations, by name, sorted.
     *
     * @param  \DOMElement  $element
     * @return array<string, string>
     */
    private static function attributes(\DOMElement $element): array
    {
        $attributes = [];

        foreach ($element->attributes as $attribute) {
            $attributes[$attribute->nodeName] = (string) $attribute->nodeValue;
        }

        ksort($attributes);

        return $attributes;
    }
}
