<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Saml;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use SineMacula\Laravel\Sso\Testing\Saml\XmlSigner;

/**
 * Unit tests for the fake SAML identity provider's metadata: its defaults, the
 * entity and the aggregate byte for byte (each part in its schema position, the
 * entities in order, every value escaped and every instant in UTC), and the
 * signature algorithms it signs with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeSamlMetadata::class)]
final class FakeSamlMetadataTest extends TestCase
{
    /** @var string The metadata namespace declaration. */
    private const string MD = 'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"';

    /** @var string The opening of an IdP descriptor. */
    private const string DESCRIPTOR = '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">';

    /** @var string A signing certificate, PEM. */
    private const string SIGNING = "-----BEGIN CERTIFICATE-----\nQUJD\nREVG\n-----END CERTIFICATE-----\n";

    /** @var string An encryption certificate, PEM. */
    private const string ENCRYPTION = "-----BEGIN CERTIFICATE-----\nR0hJ\n-----END CERTIFICATE-----\n";

    /**
     * The defaults are unsigned metadata for the entity with its signing
     * certificate, an HTTP-Redirect service and the persistent format.
     *
     * @return void
     */
    public function testHoldsItsDefaults(): void
    {
        self::assertSame([
            'aggregate'               => [],
            'aggregate_valid_until'   => null,
            'algorithm'               => 'rsa-sha256',
            'cache_duration'          => null,
            'digest'                  => 'sha256',
            'encryption_certificates' => [],
            'entity_id'               => 'https://idp.example.test/saml',
            'name_id_formats'         => ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'],
            'post_sso_url'            => null,
            'sign'                    => null,
            'signing_certificates'    => [self::SIGNING],
            'sso_binding'             => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'sso_url'                 => 'https://idp.example.test/sso',
            'valid_until'             => null,
        ], self::sorted(FakeSamlMetadata::defaults('https://idp.example.test/saml', 'https://idp.example.test/sso', self::SIGNING)));
    }

    /**
     * An entity with every part writes its identifier from the entity id's
     * hash, its attributes in order, the signing then the encryption key
     * descriptors, the formats, then the services, every value escaped and the
     * instant in UTC.
     *
     * @return void
     */
    public function testWritesAFullEntity(): void
    {
        $xml = self::metadata()->with([
            'sso_url'                 => 'https://idp.example.test/sso?a=1&b="2"',
            'post_sso_url'            => 'https://idp.example.test/post',
            'encryption_certificates' => [self::ENCRYPTION],
            'name_id_formats'         => ['urn:a&b', 'urn:c'],
            'valid_until'             => CarbonImmutable::parse('2026-12-01T02:00:00+02:00'),
            'cache_duration'          => 'PT6H',
        ])->toXml();

        self::assertSame(
            '<md:EntityDescriptor ' . self::MD . ' ID="_915f502ebcd0c9d3" entityID="https://idp.example.test/saml" validUntil="2026-12-01T00:00:00Z" cacheDuration="PT6H">'
                . self::DESCRIPTOR
                . self::keyDescriptor('signing', 'QUJDREVG')
                . self::keyDescriptor('encryption', 'R0hJ')
                . '<md:NameIDFormat>urn:a&amp;b</md:NameIDFormat><md:NameIDFormat>urn:c</md:NameIDFormat>'
                . '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso?a=1&amp;b=&quot;2&quot;"/>'
                . '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/post"/>'
                . '</md:IDPSSODescriptor></md:EntityDescriptor>',
            $xml,
        );
    }

    /**
     * An aggregate holds the other entities, then this one, with its own
     * `validUntil` in UTC; the other entities have none of their own.
     *
     * @return void
     */
    public function testWritesAnAggregate(): void
    {
        $xml = self::metadata()->with([
            'aggregate'             => ['https://other.example.test'],
            'aggregate_valid_until' => CarbonImmutable::parse('2027-01-01T01:00:00+01:00'),
            'valid_until'           => CarbonImmutable::parse('2026-12-01T00:00:00Z'),
        ])->toXml();

        self::assertSame(
            '<md:EntitiesDescriptor ' . self::MD . ' ID="_aggregate" validUntil="2027-01-01T00:00:00Z">'
                . self::plainEntity('_64794f774a90bc9a', 'https://other.example.test', '')
                . self::plainEntity('_915f502ebcd0c9d3', 'https://idp.example.test/saml', ' validUntil="2026-12-01T00:00:00Z"')
                . '</md:EntitiesDescriptor>',
            $xml,
        );
    }

    /**
     * Signed metadata names the algorithm and digest asked for, and an
     * aggregate without its own `validUntil` has none.
     *
     * @return void
     */
    public function testSignsWithTheAlgorithmsGiven(): void
    {
        $idp = new FakeSamlIdentityProvider;
        $xml = $idp->metadata()->with(['aggregate' => ['https://other.example.test'], 'sign' => 'entity', 'algorithm' => 'rsa-sha512', 'digest' => 'sha512'])->toXml();

        self::assertStringStartsWith('<md:EntitiesDescriptor ' . self::MD . ' ID="_aggregate"><md:EntityDescriptor', $xml);
        self::assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>', $xml);
        self::assertStringContainsString('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xml);
        self::assertSame(1, substr_count($xml, '<ds:Signature '));
    }

    /**
     * An entity with the defaults but its id and `validUntil`.
     *
     * @param  string  $id
     * @param  string  $entityId
     * @param  string  $validUntil
     * @return string
     */
    private static function plainEntity(string $id, string $entityId, string $validUntil): string
    {
        return '<md:EntityDescriptor ' . self::MD . ' ID="' . $id . '" entityID="' . $entityId . '"' . $validUntil . '>'
            . self::DESCRIPTOR
            . self::keyDescriptor('signing', 'QUJDREVG')
            . '<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>'
            . '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/>'
            . '</md:IDPSSODescriptor></md:EntityDescriptor>';
    }

    /**
     * The values sorted by key, so a comparison ignores their order.
     *
     * @param  array<string, mixed>  $values
     * @return array<string, mixed>
     */
    private static function sorted(array $values): array
    {
        ksort($values);

        return $values;
    }

    /**
     * One key descriptor of the use, carrying the certificate body.
     *
     * @param  string  $use
     * @param  string  $body
     * @return string
     */
    private static function keyDescriptor(string $use, string $body): string
    {
        return '<md:KeyDescriptor use="' . $use . '"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>'
            . $body . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';
    }

    /**
     * Unsigned metadata for the entity, with the fixed certificate; the signer
     * is never used.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata
     */
    private static function metadata(): FakeSamlMetadata
    {
        return new FakeSamlMetadata(
            new XmlSigner('unused', self::SIGNING),
            FakeSamlMetadata::defaults('https://idp.example.test/saml', 'https://idp.example.test/sso', self::SIGNING),
        );
    }
}
