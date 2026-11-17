<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Exception\SignatureVerificationFailedException;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SignedDescriptor;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\TestCase;

/**
 * Feature tests for the signed descriptor the metadata reader verifies through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignedDescriptor::class)]
final class SignedDescriptorTest extends TestCase
{
    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /**
     * Rows of `[changes, id, signed]`: an entity and an aggregate, signed or
     * not, and what is read of each.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: bool}>
     */
    public static function provideDescriptors(): iterable
    {
        $entity = '_' . substr(hash('sha256', FakeSamlIdentityProvider::ENTITY_ID), 0, 16);

        yield from [
            'an unsigned entity'    => [[], $entity, false],
            'a signed entity'       => [['sign' => 'entity'], $entity, true],
            'an unsigned aggregate' => [['aggregate' => ['https://other.example.test/saml']], '_aggregate', false],
            'a signed aggregate'    => [['aggregate' => ['https://other.example.test/saml'], 'sign' => 'aggregate'], '_aggregate', true],
        ];
    }

    /**
     * A descriptor is read for its `ID`, whether it is signed, and the very
     * element it came from.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $id
     * @param  bool  $signed
     * @return void
     */
    #[DataProvider('provideDescriptors')]
    public function testReadsTheIdTheSignatureAndTheElement(array $changes, string $id, bool $signed): void
    {
        $root       = self::root(self::idp()->metadata()->with($changes)->toXml());
        $descriptor = SignedDescriptor::fromXML($root);

        self::assertSame([$id, $signed], [$descriptor->getId()?->getValue(), $descriptor->isSigned()]);
        self::assertTrue($root->isSameNode($descriptor->getXML()));
    }

    /**
     * A descriptor with no `ID` is read with none.
     *
     * @return void
     */
    public function testADescriptorWithNoIdHasNone(): void
    {
        $xml = (string) preg_replace('/ ID="[^"]+"/', '', self::idp()->metadata()->toXml());

        self::assertNull(SignedDescriptor::fromXML(self::root($xml))->getId());
    }

    /**
     * Rows of `[xml, problem]`: an element that is not a descriptor, one of
     * another namespace, and a descriptor with two signatures.
     *
     * @return iterable<string, array{0: \Closure(): string, 1: string}>
     */
    public static function provideRefusals(): iterable
    {
        $only = 'Only an EntityDescriptor or an EntitiesDescriptor is a signed descriptor.';

        yield from [
            'an organization'   => [static fn (): string => '<md:Organization xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>', $only],
            'another namespace' => [static fn (): string => '<EntityDescriptor xmlns="urn:example" entityID="x"/>', $only],
            'two signatures'    => [
                static function (): string {
                    $xml       = self::idp()->metadata()->with(['sign' => 'entity'])->toXml();
                    $signature = (string) preg_replace('#^.*?(<ds:Signature\b.*?</ds:Signature>).*$#s', '$1', $xml);

                    return str_replace($signature, $signature . $signature, $xml);
                },
                'A descriptor holds one signature at most.',
            ],
        ];
    }

    /**
     * Anything but an `EntityDescriptor` or an `EntitiesDescriptor` of the
     * metadata namespace, or a descriptor with two signatures, is refused.
     *
     * @param  \Closure(): string  $xml
     * @param  string  $problem
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testAnythingElseIsRefused(\Closure $xml, string $problem): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException($problem));

        SignedDescriptor::fromXML(self::root($xml()));
    }

    /**
     * A signed descriptor is never written.
     *
     * @return void
     */
    public function testItIsNeverWritten(): void
    {
        $descriptor = SignedDescriptor::fromXML(self::root(self::idp()->metadata()->toXml()));

        $this->expectExceptionObject(new \LogicException('A signed descriptor is only ever read.'));

        $descriptor->toUnsignedXML();
    }

    /**
     * A signed descriptor verifies against its signer's key as the element it
     * was read from, unsigned once verified.
     *
     * @return void
     *
     * @throws \DOMException
     */
    public function testASignedDescriptorVerifiesAsTheElementItWasReadFrom(): void
    {
        $root       = self::root(self::idp()->metadata()->with(['sign' => 'entity'])->toXml());
        $descriptor = SignedDescriptor::fromXML($root);
        $verified   = $descriptor->verify(self::verifier());

        self::assertInstanceOf(SignedDescriptor::class, $verified);
        self::assertSame([$descriptor->getId()?->getValue(), false], [$verified->getId()?->getValue(), $verified->isSigned()]);

        $root->setAttribute('entityID', 'https://attacker.example.test/saml');

        try {
            $tampered = $descriptor->verify(self::verifier());
        } catch (SignatureVerificationFailedException) {
            $tampered = null;
        }

        self::assertNull($tampered);
    }

    /**
     * The provider's RSA-SHA256 signature verifier.
     *
     * @return \SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface
     */
    private static function verifier(): SignatureAlgorithmInterface
    {
        $key = (new X509Certificate(PEM::fromString(self::idp()->certificate())))->getPublicKey();

        return (new SignatureAlgorithmFactory)->getAlgorithm(C::SIG_RSA_SHA256, $key);
    }

    /**
     * The root element of the XML.
     *
     * @param  string  $xml
     * @return \DOMElement
     */
    private static function root(string $xml): \DOMElement
    {
        $document = new \DOMDocument;

        self::assertTrue($document->loadXML($xml, LIBXML_NONET));
        self::assertNotNull($document->documentElement);

        return $document->documentElement;
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
