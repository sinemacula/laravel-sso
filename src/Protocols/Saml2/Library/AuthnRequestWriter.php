<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use Carbon\CarbonImmutable;
use SimpleSAML\SAML2\Constants as C;
use SimpleSAML\SAML2\Type\AuthnContextComparisonTypeValue;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLDateTimeValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\saml\AuthnContextClassRef;
use SimpleSAML\SAML2\XML\saml\Issuer;
use SimpleSAML\SAML2\XML\samlp\AuthnContextComparisonTypeEnum;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\NameIDPolicy;
use SimpleSAML\SAML2\XML\samlp\RequestedAuthnContext;
use SimpleSAML\XMLSchema\Type\BooleanValue;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * Writes a connection's SAML `AuthnRequest` for its binding, and signs it when
 * a key is given (SSO-5.3, SSO-5.10, SAML 2.0 Core §3.4.1, Bindings §3.4 and
 * §3.5, `docs/design/saml-requests.md`): the SAML adapter's one entry for
 * outgoing messages, so every call into `simplesamlphp/saml2` and
 * `simplesamlphp/xml-security` it needs is made here.
 *
 * - The request is version 2.0, with the `ID` and `IssueInstant` given (UTC),
 *   the service provider entity id as `Issuer`, the connection's single sign-on
 *   URL as `Destination`, the assertion consumer service URL with the HTTP-POST
 *   `ProtocolBinding` (the only binding responses are accepted by), a
 *   `NameIDPolicy` of the connection's format with `AllowCreate`,
 *   `ForceAuthn="true"` when asked, and a `RequestedAuthnContext` with
 *   `Comparison="exact"` listing the connection's classes when it lists any.
 * - HTTP-Redirect: the XML deflated raw (level 9), base64 encoded, and sent as
 *   `SAMLRequest`, then `RelayState`, then, signed, `SigAlg` and `Signature`
 *   over exactly the encoded `SAMLRequest=…&RelayState=…&SigAlg=…`. The XML
 *   carries no signature of its own.
 * - HTTP-POST: the XML, signed with an enveloped signature after `Issuer`
 *   (exclusive canonicalisation, the enveloped-signature transform, and the
 *   digest of the signature algorithm, SHA-256 or stronger), base64 encoded as
 *   `SAMLRequest`, with `RelayState`.
 *
 * A signature uses the first algorithm the connection allows, and the private
 * key is revealed only here, for the call that signs. The library writes no
 * `ForceAuthn` (saml2 v6 compares the typed value with `true`), so the request
 * is written by a subclass that adds it before anything is signed.
 *
 * A connection with no single sign-on URL is a `LogicException`; anything else
 * that cannot be written, a connection allowing no signature algorithm or a key
 * or value the library refuses, is one `LogicException` with the package's own
 * message and no previous exception, so neither the key, the `RelayState` nor
 * the message can reach a log through it. It holds nothing (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthnRequestWriter
{
    /** @var int The DEFLATE level of an HTTP-Redirect message. */
    private const int DEFLATE_LEVEL = 9;

    /** @var string Why a request could not be written, whatever the library refused. */
    private const string UNWRITABLE = 'The SAML AuthnRequest could not be written: check the connection\'s settings and its current service provider signing key.';

    /**
     * Write the request for the connection's binding, signed with the key when
     * one is given.
     *
     * @param  string  $id
     * @param  \Carbon\CarbonImmutable  $issuedAt
     * @param  \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints  $endpoints
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  bool  $forceAuthn
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $relayState
     * @param  ?\SineMacula\Laravel\Sso\Secrets\Secret  $key
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest
     *
     * @throws \LogicException
     */
    public function write(
        string $id,
        CarbonImmutable $issuedAt,
        ConnectionEndpoints $endpoints,
        Saml2Options $options,
        bool $forceAuthn,
        #[\SensitiveParameter] Secret $relayState,
        #[\SensitiveParameter] ?Secret $key = null,
    ): OutgoingRequest {
        $destination = $options->ssoUrl ?? throw new \LogicException('An AuthnRequest is sent to the connection\'s single sign-on URL, which it has none of.');

        LibraryContainer::ensure();

        try {
            $request = self::request($id, $issuedAt->utc(), $endpoints, $destination, $options, $forceAuthn);
            $signer  = $key === null ? null : self::signer($key, self::algorithm($options));

            return $options->ssoBindingUri() === OutgoingRequest::HTTP_POST
                ? self::post($id, $request, $relayState, $signer)
                : self::redirect($id, $request, $relayState, $signer);
        } catch (\Exception) {
            throw new \LogicException(self::UNWRITABLE);
        }
    }

    /**
     * The request as the library writes it, with `ForceAuthn` added.
     *
     * @param  string  $id
     * @param  \Carbon\CarbonImmutable  $issuedAt
     * @param  \SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints  $endpoints
     * @param  string  $destination
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  bool  $forceAuthn
     * @return \SimpleSAML\SAML2\XML\samlp\AuthnRequest
     *
     * @throws \Exception
     */
    private static function request(
        string $id,
        CarbonImmutable $issuedAt,
        ConnectionEndpoints $endpoints,
        string $destination,
        Saml2Options $options,
        bool $forceAuthn,
    ): AuthnRequest {
        $arguments = [
            'id'                          => IDValue::fromString($id),
            'issueInstant'                => SAMLDateTimeValue::fromDateTime($issuedAt),
            'requestedAuthnContext'       => self::requestedAuthnContext($options->listOf(Saml2Setting::REQUESTED_AUTHN_CONTEXT)),
            'nameIdPolicy'                => new NameIDPolicy(SAMLAnyURIValue::fromString($options->nameIdFormatUri()), null, BooleanValue::fromBoolean(true)),
            'forceAuthn'                  => $forceAuthn ? BooleanValue::fromBoolean(true) : null,
            'assertionConsumerServiceURL' => SAMLAnyURIValue::fromString($endpoints->assertionConsumerService),
            'protocolBinding'             => SAMLAnyURIValue::fromString(C::BINDING_HTTP_POST),
            'issuer'                      => new Issuer(SAMLStringValue::fromString($endpoints->entityId)),
            'destination'                 => SAMLAnyURIValue::fromString($destination),
        ];

        return new class (...$arguments) extends AuthnRequest {
            /** @var string The element's local name, which the library otherwise reads from the class's name. */
            public const string LOCALNAME = 'AuthnRequest';

            /**
             * The element's namespace, `samlp`'s, named without reading the
             * class's name, which an anonymous class does not have.
             *
             * @return string
             */
            #[\Override]
            public static function getNamespaceURI(): string
            {
                return AuthnRequest::NS;
            }

            /**
             * The element's namespace prefix, `samlp`, named without reading
             * the class's name.
             *
             * @return string
             */
            #[\Override]
            public static function getNamespacePrefix(): string
            {
                return AuthnRequest::NS_PREFIX;
            }

            /**
             * The unsigned element, with `ForceAuthn="true"` when it is on.
             *
             * @param  ?\DOMElement  $parent
             * @return \DOMElement
             *
             * @throws \DOMException
             */
            #[\Override]
            protected function toUnsignedXML(?\DOMElement $parent = null): \DOMElement
            {
                $element = parent::toUnsignedXML($parent);

                if ($this->getForceAuthn()?->toBoolean() === true) {
                    $element->setAttribute('ForceAuthn', 'true');
                }

                return $element;
            }
        };
    }

    /**
     * The `RequestedAuthnContext` listing the classes, compared exactly, or
     * none when there are none.
     *
     * @param  list<string>  $classes
     * @return ?\SimpleSAML\SAML2\XML\samlp\RequestedAuthnContext
     */
    private static function requestedAuthnContext(array $classes): ?RequestedAuthnContext
    {
        if ($classes === []) {
            return null;
        }

        return new RequestedAuthnContext(
            array_map(static fn (string $class): AuthnContextClassRef => AuthnContextClassRef::fromString($class), $classes),
            AuthnContextComparisonTypeValue::fromEnum(AuthnContextComparisonTypeEnum::Exact),
        );
    }

    /**
     * The request for the HTTP-Redirect binding: deflated into `SAMLRequest`,
     * then `RelayState`, then `SigAlg` and the `Signature` over the three.
     *
     * @param  string  $id
     * @param  \SimpleSAML\SAML2\XML\samlp\AuthnRequest  $request
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $relayState
     * @param  ?\SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface  $signer
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest
     *
     * @throws \Exception
     */
    private static function redirect(
        string $id,
        AuthnRequest $request,
        #[\SensitiveParameter] Secret $relayState,
        #[\SensitiveParameter] ?SignatureAlgorithmInterface $signer,
    ): OutgoingRequest {
        $fields = [
            'SAMLRequest' => base64_encode(self::deflate(self::xml($request->toXML()))),
            'RelayState'  => $relayState->reveal(),
        ];

        if ($signer !== null) {
            $fields['SigAlg']    = $signer->getAlgorithmId();
            $fields['Signature'] = base64_encode(self::signature($signer, OutgoingRequest::encode($fields)));
        }

        return new OutgoingRequest($id, OutgoingRequest::HTTP_REDIRECT, $fields);
    }

    /**
     * The request for the HTTP-POST binding: signed with an enveloped signature
     * when there is a signer, and base64 encoded into `SAMLRequest`, with
     * `RelayState`.
     *
     * @param  string  $id
     * @param  \SimpleSAML\SAML2\XML\samlp\AuthnRequest  $request
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $relayState
     * @param  ?\SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface  $signer
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest
     *
     * @throws \Exception
     */
    private static function post(
        string $id,
        AuthnRequest $request,
        #[\SensitiveParameter] Secret $relayState,
        #[\SensitiveParameter] ?SignatureAlgorithmInterface $signer,
    ): OutgoingRequest {
        if ($signer !== null) {
            $request->sign($signer);
        }

        return new OutgoingRequest($id, OutgoingRequest::HTTP_POST, [
            'SAMLRequest' => base64_encode(self::xml($request->toXML())),
            'RelayState'  => $relayState->reveal(),
        ]);
    }

    /**
     * What signs with the key and the algorithm.
     *
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $key
     * @param  string  $algorithm
     * @return \SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface
     *
     * @throws \Exception
     */
    private static function signer(#[\SensitiveParameter] Secret $key, string $algorithm): SignatureAlgorithmInterface
    {
        return (new SignatureAlgorithmFactory)->getAlgorithm($algorithm, new PrivateKey(PEM::fromString($key->reveal())));
    }

    /**
     * The signature algorithm: the first the connection allows, which a
     * complete connection always has.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @return string
     *
     * @throws \LogicException
     */
    private static function algorithm(Saml2Options $options): string
    {
        $algorithms = $options->listOf(Saml2Setting::SIGNATURE_ALGORITHMS);

        return $algorithms[0] ?? throw new \LogicException(self::UNWRITABLE);
    }

    /**
     * The element's XML, with no XML declaration.
     *
     * @param  \DOMElement  $element
     * @return string
     *
     * @throws \LogicException
     */
    private static function xml(\DOMElement $element): string
    {
        try {
            $xml = $element->ownerDocument?->saveXML($element);
        } catch (\DOMException) {
            $xml = false;
        }

        if (!is_string($xml)) {
            throw new \LogicException('The AuthnRequest could not be serialised.');
        }

        return $xml;
    }

    /**
     * The signer's signature over the query, as raw bytes.
     *
     * @param  \SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface  $signer
     * @param  string  $query
     * @return string
     *
     * @throws \LogicException
     */
    private static function signature(#[\SensitiveParameter] SignatureAlgorithmInterface $signer, #[\SensitiveParameter] string $query): string
    {
        $signature = $signer->sign($query);

        if ($signature === false) {
            throw new \LogicException('The AuthnRequest could not be signed.');
        }

        return $signature;
    }

    /**
     * The XML deflated raw (RFC 1951), as the HTTP-Redirect binding sends it.
     *
     * @param  string  $xml
     * @return string
     *
     * @throws \LogicException
     */
    private static function deflate(#[\SensitiveParameter] string $xml): string
    {
        $deflated = gzdeflate($xml, self::DEFLATE_LEVEL);

        if ($deflated === false) {
            throw new \LogicException('The AuthnRequest could not be deflated.');
        }

        return $deflated;
    }
}
