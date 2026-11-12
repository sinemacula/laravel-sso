<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\EntityIDValue;
use SimpleSAML\SAML2\Type\KeyTypesValue;
use SimpleSAML\SAML2\Type\SAMLAnyURIListValue;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\XML\md\AssertionConsumerService;
use SimpleSAML\SAML2\XML\md\EncryptionMethod;
use SimpleSAML\SAML2\XML\md\EntityDescriptor;
use SimpleSAML\SAML2\XML\md\KeyDescriptor;
use SimpleSAML\SAML2\XML\md\KeyTypesEnum;
use SimpleSAML\SAML2\XML\md\NameIDFormat;
use SimpleSAML\SAML2\XML\md\SPSSODescriptor;
use SimpleSAML\XMLSchema\Type\AnyURIValue;
use SimpleSAML\XMLSchema\Type\BooleanValue;
use SimpleSAML\XMLSchema\Type\UnsignedShortValue;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;

/**
 * Writes a SAML connection's unsigned SP metadata. It has no `ID`, `validUntil`
 * or `cacheDuration`, so the same inputs always write the same bytes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MetadataWriter
{
    /** @var string Exactly one PEM certificate block, its body captured. */
    private const string CERTIFICATE = '/\A-----BEGIN CERTIFICATE-----([A-Za-z0-9+\/=\s]+)-----END CERTIFICATE-----\z/';

    /** @var string Refusal of a value that is not one PEM certificate block. */
    private const string NOT_A_CERTIFICATE = 'A service provider certificate in the metadata must be exactly one PEM-encoded certificate.';

    /** @var string Refusal of metadata the schema does not allow; quotes nothing. */
    private const string UNWRITABLE = 'The service provider metadata cannot be written: its entity id, an endpoint or a certificate is not one SAML 2.0 Metadata allows.';

    /**
     * The service provider metadata as XML.
     *
     * @param  \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints  $endpoints
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  list<string>  $signing
     * @param  list<string>  $encryption
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function write(ConnectionEndpoints $endpoints, Saml2Options $options, array $signing, array $encryption): string
    {
        $signingBodies    = self::bodies($signing);
        $encryptionBodies = self::bodies($encryption);

        LibraryContainer::ensure();

        try {
            $element = self::entity($endpoints, $options, $signingBodies, $encryptionBodies)->toXML();
            $xml     = $element->ownerDocument?->saveXML($element);
        } catch (\Exception) {
            throw new \InvalidArgumentException(self::UNWRITABLE);
        }

        return (string) $xml;
    }

    /**
     * The `EntityDescriptor` with its one `SPSSODescriptor`.
     *
     * @param  \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints  $endpoints
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  list<string>  $signing
     * @param  list<string>  $encryption
     * @return \SimpleSAML\SAML2\XML\md\EntityDescriptor
     *
     * @throws \Exception
     */
    private static function entity(ConnectionEndpoints $endpoints, Saml2Options $options, array $signing, array $encryption): EntityDescriptor
    {
        $methods = self::encryptionMethods($options);
        $keys    = [
            ...array_map(static fn (string $body): KeyDescriptor => self::keyDescriptor(KeyTypesEnum::SIGNING, $body, []), $signing),
            ...array_map(static fn (string $body): KeyDescriptor => self::keyDescriptor(KeyTypesEnum::ENCRYPTION, $body, $methods), $encryption),
        ];

        $descriptor = new SPSSODescriptor(
            [self::assertionConsumerService($endpoints->assertionConsumerService)],
            SAMLAnyURIListValue::fromString(Constants::NS_SAMLP),
            BooleanValue::fromBoolean($options->isOn(Saml2Setting::SIGN_AUTHN_REQUESTS)),
            BooleanValue::fromBoolean($options->isOn(Saml2Setting::WANT_ASSERTIONS_SIGNED)),
            keyDescriptors: $keys,
            nameIDFormat: [NameIDFormat::fromString($options->nameIdFormatUri())],
        );

        return new EntityDescriptor(EntityIDValue::fromString($endpoints->entityId), roleDescriptor: [$descriptor]);
    }

    /**
     * The one HTTP-POST assertion consumer service, index 0 and the default.
     *
     * @param  string  $location
     * @return \SimpleSAML\SAML2\XML\md\AssertionConsumerService
     */
    private static function assertionConsumerService(string $location): AssertionConsumerService
    {
        return new AssertionConsumerService(
            UnsignedShortValue::fromInteger(0),
            SAMLAnyURIValue::fromString(Constants::BINDING_HTTP_POST),
            SAMLAnyURIValue::fromString($location),
            BooleanValue::fromBoolean(true),
        );
    }

    /**
     * A `KeyDescriptor` of the use carrying the certificate.
     *
     * @param  \SimpleSAML\SAML2\XML\md\KeyTypesEnum  $use
     * @param  string  $body
     * @param  list<\SimpleSAML\SAML2\XML\md\EncryptionMethod>  $methods
     * @return \SimpleSAML\SAML2\XML\md\KeyDescriptor
     */
    private static function keyDescriptor(KeyTypesEnum $use, string $body, array $methods): KeyDescriptor
    {
        $keyInfo = new KeyInfo([new X509Data([X509Certificate::fromString($body)])]);

        return new KeyDescriptor($keyInfo, KeyTypesValue::fromEnum($use), $methods);
    }

    /**
     * An `EncryptionMethod` per allowed data algorithm, then per key transport.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @return list<\SimpleSAML\SAML2\XML\md\EncryptionMethod>
     */
    private static function encryptionMethods(Saml2Options $options): array
    {
        return array_map(
            static fn (string $algorithm): EncryptionMethod => new EncryptionMethod(AnyURIValue::fromString($algorithm)),
            [...$options->dataEncryptionAlgorithms(), ...$options->keyTransportAlgorithms()],
        );
    }

    /**
     * The base64 body of each certificate, so a private key or anything else is
     * refused before the library sees it.
     *
     * @param  list<string>  $certificates
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private static function bodies(array $certificates): array
    {
        $bodies = [];

        foreach ($certificates as $certificate) {

            if (preg_match(self::CERTIFICATE, trim($certificate), $matches) !== 1) {
                throw new \InvalidArgumentException(self::NOT_A_CERTIFICATE);
            }

            $bodies[] = (string) preg_replace('/\s+/', '', $matches[1]);
        }

        return $bodies;
    }
}
