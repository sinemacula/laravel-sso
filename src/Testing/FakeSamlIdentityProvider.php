<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use Carbon\CarbonImmutable;
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
 * Trust its `certificate()` on the connection under test, give the connection
 * its `entityId()`, and post a `response()` made for the connection's service
 * provider entity id and assertion consumer service URL to the completion
 * helper, `inResponseTo()` the request the start stored. A second provider is
 * an attacker: its responses carry its own certificate, which the connection
 * never trusts.
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
