<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Testing\Navigations;

/**
 * The `AuthnRequest` a start actually sent, read from either binding so a test
 * answers the real request. No signature is checked.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FakeAuthnRequest
{
    /** @var string The SAML 2.0 protocol namespace. */
    public const string NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /** @var string The SAML 2.0 assertion namespace. */
    public const string NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** @var list<string> The values of `ForceAuthn` that force authentication. */
    private const array FORCED = ['true', '1'];

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $issuer
     * @param  string  $assertionConsumerService
     * @param  ?string  $destination
     * @param  bool  $forceAuthn
     * @param  ?string  $relayState
     * @param  string  $xml
     */
    private function __construct(

        /** The request's `ID`, which a response names as its `InResponseTo`. */
        public string $id,

        /** The service provider entity id the request names as its `Issuer`. */
        public string $issuer,

        /** Where the response is posted: its `Destination` and `Recipient`. */
        public string $assertionConsumerService,

        /** The single sign-on URL the request is addressed to, if it names one. */
        public ?string $destination,

        /** Whether the request asks the provider to authenticate the person again. */
        public bool $forceAuthn,

        /** The `RelayState` the browser carries to the provider and back. */
        public ?string $relayState,

        /** The request's XML, as the provider received it. */
        public string $xml,
    ) {}

    /**
     * The request a `StartResult`, `Navigation` or start JSON carries.
     *
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Sso\Flows\StartResult|\SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @return self
     *
     * @throws \LogicException
     */
    public static function fromNavigation(array|Navigation|StartResult $navigation): self
    {
        [$url, $fields] = Navigations::parts($navigation);

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        $posted   = array_key_exists('SAMLRequest', $fields);
        $message  = $posted ? $fields : $query;
        $encoded  = $message['SAMLRequest'] ?? null;
        $relay    = $message['RelayState']  ?? null;
        $relay    = is_string($relay) ? $relay : null;
        $received = is_string($encoded) ? self::decoded($encoded, !$posted) : throw new \LogicException('The navigation carries no SAMLRequest.');

        return self::read($received, $relay);
    }

    /**
     * The XML of a base64 `SAMLRequest`, also deflated when it travelled in a
     * URL.
     *
     * @param  string  $encoded
     * @param  bool  $deflated
     * @return string
     *
     * @throws \LogicException
     */
    private static function decoded(string $encoded, bool $deflated): string
    {
        $raw = base64_decode($encoded, true);
        $xml = is_string($raw) && $deflated ? self::inflated($raw) : $raw;

        if (is_string($xml)) {
            return $xml;
        }

        $message = $deflated ? 'The SAMLRequest is not deflated and base64 encoded.' : 'The SAMLRequest is not base64 encoded.';

        throw new \LogicException($message);
    }

    /**
     * The raw DEFLATE data inflated, or `false`, with the warning suppressed.
     *
     * @param  string  $raw
     * @return false|string
     */
    private static function inflated(string $raw): false|string
    {
        set_error_handler(static fn (): bool => true);

        try {
            return gzinflate($raw);
        } finally {
            restore_error_handler();
        }
    }

    /**
     * The request the XML is.
     *
     * @param  string  $xml
     * @param  ?string  $relayState
     * @return self
     *
     * @throws \LogicException
     */
    private static function read(string $xml, ?string $relayState): self
    {
        $root = XmlDocument::root($xml, 'SAMLRequest');

        if ($root->namespaceURI !== self::NS_SAMLP || $root->localName !== 'AuthnRequest') {
            throw new \LogicException('The SAMLRequest is not an AuthnRequest.');
        }

        $destination = $root->getAttribute('Destination');

        return new self(
            XmlDocument::attribute($root, 'ID'),
            XmlDocument::text($root, self::NS_SAML, 'Issuer'),
            XmlDocument::attribute($root, 'AssertionConsumerServiceURL'),
            $destination === '' ? null : $destination,
            in_array($root->getAttribute('ForceAuthn'), self::FORCED, true),
            $relayState,
            $xml,
        );
    }
}
