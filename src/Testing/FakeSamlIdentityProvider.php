<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Testing\Saml\FakeAuthnRequest;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use SineMacula\Laravel\Sso\Testing\Saml\XmlSigner;

/**
 * A SAML identity provider for tests (SSO-12.4), so an application tests its
 * SAML flows without a network: its own RSA signing key and self-signed
 * certificate, signed and encrypted responses with every knob a test needs
 * (`Saml\FakeSamlResponse`), and its metadata, signed or not
 * (`Saml\FakeSamlMetadata`). Seeded from the adversarial fixtures of the
 * library spike, whose hostile cases (signature wrapping, duplicate ids,
 * comment truncation, weak algorithms) it can mount on any response.
 *
 * Trust its `certificate()` on the connection under test and give the
 * connection its `entityId()`. Then `receive()` the `AuthnRequest` the start
 * sent the browser with, as the provider's single sign-on service reads it, and
 * post the response `respondTo()` makes to the completion helper with the
 * request's `RelayState`: the response names the request's `ID` as its
 * `InResponseTo`, is made for its issuer and assertion consumer service URL,
 * and, when the request forces authentication, states an authentication made at
 * the instant given. An unsolicited response, which answers no request, is a
 * `response()` made for the service provider the connection's metadata
 * describes (`Saml\FakeServiceProvider`). A second provider is an attacker: its
 * responses carry its own certificate, which the connection never trusts.
 *
 * The provider has no clock: each response is made at the instant a test gives
 * it, the current time when it gives none. Give it the instant of the clock the
 * package reads, since the package's frozen clock does not follow Laravel's
 * time travel and Laravel's time does not follow it.
 *
 * Keys are generated per provider unless a test gives its own; generating one
 * takes a few tens of milliseconds, so a test class may keep a provider for all
 * its tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FakeSamlIdentityProvider
{
    /** @var string The entity id a provider has unless a test gives another. */
    public const string ENTITY_ID = 'https://idp.example.test/saml';

    /** @var string The single sign-on URL its metadata names unless a test gives another. */
    public const string SSO_URL = 'https://idp.example.test/saml/sso';

    /** @var string The PEM private key the provider signs with. */
    private string $privateKey;

    /** @var string The provider's PEM certificate. */
    private string $certificate;

    /**
     * Constructor.
     *
     * @param  string  $entityId
     * @param  ?string  $privateKey
     * @param  ?string  $certificate
     *
     * @throws \LogicException
     */
    public function __construct(

        /** The provider's entity id, the `Issuer` it writes. */
        public string $entityId = self::ENTITY_ID,

        // Its PEM private key, generated when not given with a certificate
        #[\SensitiveParameter]
        ?string $privateKey = null,

        // Its PEM certificate, generated with the key when not given
        ?string $certificate = null,
    ) {
        [$this->privateKey, $this->certificate] = $privateKey === null || $certificate === null ? self::keyPair($entityId) : [$privateKey, $certificate];
    }

    /**
     * A fresh RSA key pair of 2048 bits and a self-signed certificate valid for
     * a year from yesterday, for the common name: the private key, then the
     * certificate, both PEM.
     *
     * @param  string  $commonName
     * @return array{0: string, 1: string}
     *
     * @throws \LogicException
     */
    public static function keyPair(string $commonName = 'idp.example.test'): array
    {
        $key  = openssl_pkey_new(['private_key_bits' => 2048]) ?: self::failed();
        $name = ['commonName' => substr((string) preg_replace('/[^A-Za-z0-9.-]/', '-', $commonName), 0, 64)];
        $csr  = openssl_csr_new($name, $key);
        $cert = $csr instanceof \OpenSSLCertificateSigningRequest ? openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256']) : self::failed();

        if ($cert === false || !openssl_pkey_export($key, $private) || !openssl_x509_export($cert, $certificate)) {
            self::failed();
        }

        return [$private, $certificate];
    }

    /**
     * The provider's PEM certificate, which a connection trusts.
     *
     * @return string
     */
    public function certificate(): string
    {
        return $this->certificate;
    }

    /**
     * What signs the provider's messages, to sign a hand-built one or to sign
     * another provider's response as this one.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\XmlSigner
     */
    public function signer(): XmlSigner
    {
        return new XmlSigner($this->privateKey, $this->certificate);
    }

    /**
     * A valid response to the service provider at the instant (the current time
     * by default), unsolicited until `inResponseTo()` names a request.
     *
     * @param  string  $spEntityId
     * @param  string  $acsUrl
     * @param  ?\Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    public function response(string $spEntityId, string $acsUrl, ?CarbonImmutable $now = null): FakeSamlResponse
    {
        return new FakeSamlResponse($this->signer(), FakeSamlResponse::defaults($this->entityId, $spEntityId, $acsUrl, $now ?? CarbonImmutable::now('UTC')));
    }

    /**
     * The `AuthnRequest` the start sent the browser to the provider with, read
     * from an HTTP-Redirect URL or an HTTP-POST form.
     *
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Sso\Flows\StartResult|\SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeAuthnRequest
     *
     * @throws \LogicException
     */
    public function receive(array|Navigation|StartResult $navigation): FakeAuthnRequest
    {
        return FakeAuthnRequest::fromNavigation($navigation);
    }

    /**
     * A valid response to the request at the instant (the current time by
     * default): made for the request's issuer and assertion consumer service,
     * naming its `ID` as `InResponseTo`, and, when it forces authentication,
     * with every authentication statement made at that instant, as a provider
     * that has just asked the person again states.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeAuthnRequest  $request
     * @param  ?\Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    public function respondTo(FakeAuthnRequest $request, ?CarbonImmutable $now = null): FakeSamlResponse
    {
        $now ??= CarbonImmutable::now('UTC');

        $response = $this->response($request->issuer, $request->assertionConsumerService, $now)->inResponseTo($request->id);

        return $request->forceAuthn ? self::authenticatedAt($response, $now) : $response;
    }

    /**
     * The provider's metadata, unsigned until asked.
     *
     * @param  string  $ssoUrl
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata
     */
    public function metadata(string $ssoUrl = self::SSO_URL): FakeSamlMetadata
    {
        return new FakeSamlMetadata($this->signer(), FakeSamlMetadata::defaults($this->entityId, $ssoUrl, $this->certificate));
    }

    /**
     * The response with every authentication statement made at the instant.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse  $response
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private static function authenticatedAt(FakeSamlResponse $response, CarbonImmutable $now): FakeSamlResponse
    {
        /** @var list<array<string, mixed>> $statements */
        $statements = $response->option('authn_statements');

        return $response->with(['authn_statements' => array_map(static fn (array $statement): array => [...$statement, 'instant' => $now], $statements)]);
    }

    /**
     * Refuse a key pair OpenSSL could not generate.
     *
     * @return never
     *
     * @throws \LogicException
     */
    private static function failed(): never
    {
        throw new \LogicException('The fake identity provider could not generate its keys.');
    }
}
