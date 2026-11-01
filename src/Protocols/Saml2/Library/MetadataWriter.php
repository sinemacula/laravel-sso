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
 * Writes a SAML connection's service provider metadata (SAML 2.0 Metadata,
 * SSO-5.9) with the library's metadata element classes: one unsigned
 * `md:EntityDescriptor` for the service provider entity id, holding one
 * `md:SPSSODescriptor`.
 *
 * The descriptor carries:
 *
 * - `protocolSupportEnumeration` SAML 2.0, `AuthnRequestsSigned` and
 *   `WantAssertionsSigned` as the connection's switches say;
 * - a `KeyDescriptor` of use `signing` for each signing certificate given, then
 *   one of use `encryption` for each encryption certificate given, in the order
 *   given (the current key, then the next one during a rotation);
 * - on each encryption `KeyDescriptor`, an `EncryptionMethod` for each data
 *   encryption algorithm the connection allows (AES-128-GCM and AES-192-GCM by
 *   default, AES-CBC only when listed, never AES-256-GCM:
 *   `docs/design/saml-library.md`, condition 5), then each key transport it
 *   allows (RSA-OAEP, never RSA 1.5);
 * - the connection's NameID format, and one HTTP-POST
 *   `AssertionConsumerService` at the connection's assertion consumer service,
 *   index 0 and the default.
 *
 * It has no `ID`, `validUntil` or `cacheDuration`, so the same connection, keys
 * and endpoints always write the same bytes. Only a certificate's body is
 * written: each one given must be exactly one PEM certificate block, so a
 * private key, or anything else, is refused before the library sees it, and no
 * secret is ever written. A value the schema does not allow, such as an entity
 * id longer than 1024 characters, is an `InvalidArgumentException` that quotes
 * nothing given. It holds nothing between calls (SSO-11.2).
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

    /** @var string The refusal of a certificate that is not one PEM certificate block. */
    private const string NOT_A_CERTIFICATE = 'A service provider certificate in the metadata must be exactly one PEM-encoded certificate.';

    /** @var string The refusal of metadata the schema does not allow. */
    private const string UNWRITABLE = 'The service provider metadata cannot be written: its entity id, an endpoint or a certificate is not one SAML 2.0 Metadata allows.';

    /**
     * The metadata of the service provider with the endpoints, options and
     * certificates given, as XML.
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
     * The one HTTP-POST assertion consumer service at the location, index 0 and
     * the default.
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
     * A `KeyDescriptor` of the use carrying the certificate, with the
     * encryption methods given.
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
     * An `EncryptionMethod` for each data encryption algorithm the connection
     * allows, then for each key transport it allows, in the order it lists
     * them.
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
     * The base64 body of each certificate, whitespace removed, refusing any
     * value that is not exactly one PEM certificate block.
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
