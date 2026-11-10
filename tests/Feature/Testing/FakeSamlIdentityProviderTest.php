<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\AssertionEncryptor;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use SineMacula\Laravel\Sso\Testing\Saml\ResponseWriter;
use SineMacula\Laravel\Sso\Testing\Saml\SignatureWrapping;
use SineMacula\Laravel\Sso\Testing\Saml\XmlSigner;
use Tests\TestCase;

/**
 * Feature tests for the fake SAML identity provider (SSO-12.4): its keys, the
 * options of its responses and how each change answers a new response, what the
 * browser posts, its metadata (alone, in an aggregate, signed by itself or by
 * another key), every signature algorithm its signer writes, and a wrapping
 * variant it does not have. That its responses and metadata are valid SAML, and
 * every hostile knob refused, the adapter's tests show.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeSamlIdentityProvider::class)]
#[CoversClass(FakeSamlResponse::class)]
#[CoversClass(FakeSamlMetadata::class)]
#[CoversClass(ResponseWriter::class)]
#[CoversClass(XmlSigner::class)]
#[CoversClass(AssertionEncryptor::class)]
#[CoversClass(SignatureWrapping::class)]
final class FakeSamlIdentityProviderTest extends TestCase
{
    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /**
     * A key pair is a private key and a self-signed certificate of its public
     * key; a provider given one uses it, and one given none makes its own.
     *
     * @return void
     */
    public function testHasItsKeys(): void
    {
        [$private, $certificate] = FakeSamlIdentityProvider::keyPair('given.example.test');

        $given = new FakeSamlIdentityProvider('https://given.example.test/saml', $private, $certificate);

        self::assertTrue(openssl_x509_check_private_key($certificate, $private));
        self::assertSame($certificate, $given->certificate());
        self::assertSame('https://given.example.test/saml', $given->entityId);
        self::assertSame(FakeSamlIdentityProvider::ENTITY_ID, self::idp()->entityId);
        self::assertNotSame($certificate, self::idp()->certificate());
        self::assertSame('given.example.test', openssl_x509_parse($certificate)['subject']['CN'] ?? null);
    }

    /**
     * A key pair is a 2048-bit RSA key and a certificate signed with
     * RSA-SHA256, valid for exactly 365 days, whose common name is the one
     * given with every character outside letters, digits, dots and hyphens
     * replaced and cut to 64 characters.
     *
     * @return void
     */
    public function testMakesAKeyPairAsDescribed(): void
    {
        [$private, $certificate] = FakeSamlIdentityProvider::keyPair(str_repeat('a', 60) . ' b/c:d');

        $key     = openssl_pkey_get_private($private) ?: self::fail('The private key does not load.');
        $details = openssl_pkey_get_details($key) ?: self::fail('The private key has no details.');
        $parsed  = openssl_x509_parse($certificate) ?: self::fail('The certificate does not parse.');

        self::assertSame([OPENSSL_KEYTYPE_RSA, 2048], [$details['type'], $details['bits']]);
        self::assertSame(['RSA-SHA256', 365 * 86400], [$parsed['signatureTypeSN'], $parsed['validTo_time_t'] - $parsed['validFrom_time_t']]);
        self::assertSame(str_repeat('a', 60) . '-b-c', $parsed['subject']['CN']);
        self::assertSame('idp.example.test', openssl_x509_parse(FakeSamlIdentityProvider::keyPair()[1])['subject']['CN'] ?? null);
    }

    /**
     * A provider given a key without its certificate, or a certificate without
     * its key, makes its own pair, named for its entity id, rather than half of
     * one.
     *
     * @return void
     */
    public function testMakesItsOwnPairWhenGivenHalfOfOne(): void
    {
        [$private, $certificate] = FakeSamlIdentityProvider::keyPair('given.example.test');

        $keyOnly         = new FakeSamlIdentityProvider('https://key.example.test/saml', $private);
        $certificateOnly = new FakeSamlIdentityProvider('https://certificate.example.test/saml', null, $certificate);

        self::assertFalse(openssl_x509_check_private_key($keyOnly->certificate(), $private));
        self::assertNotSame($certificate, $certificateOnly->certificate());
        self::assertSame('https---key.example.test-saml', openssl_x509_parse($keyOnly->certificate())['subject']['CN'] ?? null);
    }

    /**
     * A response holds its defaults, and each change answers a new response,
     * the old one kept.
     *
     * @return void
     */
    public function testEachChangeAnswersANewResponse(): void
    {
        $now      = CarbonImmutable::parse('2026-11-01T12:00:00Z');
        $response = self::idp()->response('https://sp.example.test', 'https://sp.example.test/acs', $now);
        $changed  = $response->inResponseTo('_request')->signed(true, false)->with(['name_id' => 'bob']);

        $names         = ['in_response_to', 'sign_response', 'sign_assertion', 'name_id'];
        $confirmations = $changed->option('confirmations');

        self::assertIsArray($confirmations);

        self::assertSame([null, false, true, 'alice'], array_map($response->option(...), $names));
        self::assertSame(['_request', true, false, 'bob'], array_map($changed->option(...), $names));
        self::assertSame(['_request'], array_column($confirmations, 'in_response_to'));
        self::assertSame([['https://sp.example.test']], $response->option('audiences'));
        self::assertEquals(CarbonImmutable::parse('2026-11-01T12:05:00Z'), $response->option('not_on_or_after'));
        self::assertNull($response->option('unknown'));
        self::assertNotSame($response->option('response_id'), self::idp()->response('https://sp.example.test', 'https://sp.example.test/acs')->option('response_id'));
    }

    /**
     * The browser posts the response base64 encoded, with a `RelayState` only
     * when there is one, and the completion request carries the same.
     *
     * @return void
     */
    public function testWhatTheBrowserPosts(): void
    {
        $response = self::idp()->response('https://sp.example.test', 'https://sp.example.test/acs')->signed(false, false);
        $xml      = $response->toXml();

        self::assertSame($xml, base64_decode($response->encoded(), true));
        self::assertSame(['SAMLResponse'], array_keys($response->post()));
        self::assertSame(['SAMLResponse', 'RelayState'], array_keys($response->post('relay')));
        self::assertSame('relay', $response->post('relay')['RelayState']);
        self::assertSame('POST', $response->completionRequest('relay')->method);
        self::assertSame('', $response->completionRequest('relay')->query());
        self::assertSame(['SAMLResponse' => base64_encode($xml)], $response->completionRequest()->body());
        self::assertStringNotContainsString('<saml:Assertion', $response->with(['assertion' => false])->toXml());
    }

    /**
     * The metadata is a valid `EntityDescriptor` for the provider, with its
     * signing certificate, its single sign-on service and its NameID format.
     *
     * @return void
     */
    public function testWritesValidMetadata(): void
    {
        $xml = self::idp()->metadata()->with([
            'post_sso_url'            => 'https://idp.example.test/saml/post',
            'encryption_certificates' => [self::idp()->certificate()],
            'valid_until'             => CarbonImmutable::parse('2026-12-01T00:00:00Z'),
            'cache_duration'          => 'PT6H',
        ])->toXml();

        $document = (new HardenedParser)->parse($xml, MessageKind::METADATA, 1048576);
        $root     = $document->documentElement;

        self::assertNotNull($root);
        self::assertSame(
            ['EntityDescriptor', FakeSamlIdentityProvider::ENTITY_ID, '2026-12-01T00:00:00Z', 'PT6H'],
            [$root->localName, $root->getAttribute('entityID'), $root->getAttribute('validUntil'), $root->getAttribute('cacheDuration')],
        );
        self::assertSame(2, $document->getElementsByTagNameNS(FakeSamlMetadata::NS_MD, 'KeyDescriptor')->length);
        self::assertSame(2, $document->getElementsByTagNameNS(FakeSamlMetadata::NS_MD, 'SingleSignOnService')->length);
        self::assertStringContainsString('Location="' . FakeSamlIdentityProvider::SSO_URL . '"', $xml);
        self::assertStringContainsString(FakeSamlResponse::PERSISTENT, $xml);
        self::assertStringNotContainsString('Signature', $xml);
    }

    /**
     * Rows of `[changes, root, signed]`: metadata, the element at its root, and
     * which element the signature is a child of.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: ?string}>
     */
    public static function provideSignedMetadata(): iterable
    {
        yield from [
            'the entity signed'                  => [['sign' => 'entity'], 'EntityDescriptor', 'EntityDescriptor'],
            'an aggregate, the entity signed'    => [['aggregate' => ['https://other.example.test'], 'sign' => 'entity'], 'EntitiesDescriptor', 'EntityDescriptor'],
            'an aggregate, the aggregate signed' => [['aggregate' => ['https://other.example.test'], 'sign' => 'aggregate'], 'EntitiesDescriptor', 'EntitiesDescriptor'],
            'an aggregate, unsigned'             => [['aggregate' => ['https://other.example.test']], 'EntitiesDescriptor', null],
        ];
    }

    /**
     * Metadata in an aggregate, signed in the entity or the aggregate, is
     * written as asked and stays valid.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $root
     * @param  ?string  $signed
     * @return void
     */
    #[DataProvider('provideSignedMetadata')]
    public function testSignsTheMetadataAsAsked(array $changes, string $root, ?string $signed): void
    {
        $document  = (new HardenedParser)->parse(self::idp()->metadata()->with($changes)->toXml(), MessageKind::METADATA, 1048576);
        $signature = $document->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')->item(0);

        self::assertSame($root, $document->documentElement?->localName);
        self::assertSame($signed, $signature?->parentNode?->localName);
    }

    /**
     * Metadata signed by another key carries that key's certificate.
     *
     * @return void
     */
    public function testMetadataSignedByAnotherKeyCarriesItsCertificate(): void
    {
        $attacker = new FakeSamlIdentityProvider('https://attacker.example.test/saml');
        $xml      = self::idp()->metadata()->with(['sign' => 'entity'])->signedBy($attacker->signer())->toXml();
        $body     = (string) preg_replace('/-----[^-]+-----|\s+/', '', $attacker->certificate());

        self::assertStringContainsString('<ds:X509Certificate>' . $body . '</ds:X509Certificate>', $xml);
    }

    /**
     * Rows of `[algorithm, hash]`: each signature algorithm the signer writes,
     * and the hash OpenSSL verifies it with.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideAlgorithms(): iterable
    {
        yield from [
            'rsa-sha1'   => ['rsa-sha1', OPENSSL_ALGO_SHA1],
            'rsa-sha256' => ['rsa-sha256', OPENSSL_ALGO_SHA256],
            'rsa-sha384' => ['rsa-sha384', OPENSSL_ALGO_SHA384],
            'rsa-sha512' => ['rsa-sha512', OPENSSL_ALGO_SHA512],
        ];
    }

    /**
     * The signer signs with the hash of each algorithm.
     *
     * @param  string  $algorithm
     * @param  int  $hash
     * @return void
     */
    #[DataProvider('provideAlgorithms')]
    public function testSignsWithEachAlgorithm(string $algorithm, int $hash): void
    {
        $signature = base64_decode(self::idp()->signer()->signatureValue('data', $algorithm), true);

        self::assertSame(1, openssl_verify('data', (string) $signature, self::idp()->certificate(), $hash));
    }

    /**
     * A wrapping variant the provider does not have is refused.
     *
     * @return void
     */
    public function testAnUnknownWrappingVariantIsRefused(): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('No wrapping variant [xsw9].'));

        (new SignatureWrapping)->apply('xsw9', new \DOMDocument, '<x/>');
    }

    /**
     * The provider, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
