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
 * A SAML identity provider for tests, with its own key and certificate. Key
 * generation takes tens of milliseconds, so a test class may share one.
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

        // Not promoted: generated unless given with a certificate
        #[\SensitiveParameter]
        ?string $privateKey = null,

        // Not promoted: generated with the key unless given
        ?string $certificate = null,
    ) {
        [$this->privateKey, $this->certificate] = $privateKey === null || $certificate === null ? self::keyPair($entityId) : [$privateKey, $certificate];
    }

    /**
     * Generate a 2048-bit RSA private key and a year's self-signed certificate,
     * both PEM.
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
     * The provider's signer, to sign a hand-built message as this provider.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\XmlSigner
     */
    public function signer(): XmlSigner
    {
        return new XmlSigner($this->privateKey, $this->certificate);
    }

    /**
     * A valid unsolicited response at the instant; pass the package clock's
     * time, as the provider has no clock of its own.
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
     * Read the start's `AuthnRequest` from an HTTP-Redirect URL or HTTP-POST
     * form.
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
     * A valid response to the request; under `ForceAuthn`, every authentication
     * statement is made at the instant.
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
     * Set every authentication statement's instant.
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
