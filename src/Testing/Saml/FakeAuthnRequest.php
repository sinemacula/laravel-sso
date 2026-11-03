<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Testing\Navigations;

/**
 * The SAML `AuthnRequest` a start sent the browser to the identity provider
 * with, read as the fake identity provider's single sign-on service reads it
 * (SSO-12.4), so a test answers the request the package really sent, never one
 * it guessed: its `ID`, which the response's `InResponseTo` names, its `Issuer`
 * (the service provider entity id, the response's audience), its assertion
 * consumer service URL (where the response is posted, its `Destination` and its
 * bearer `Recipient`), its `Destination`, whether it forces authentication, and
 * the `RelayState` the browser carries back.
 *
 * It reads either binding: the `SAMLRequest` of an HTTP-Redirect URL's query,
 * deflated and base64 encoded, or the `SAMLRequest` field of an HTTP-POST form,
 * base64 encoded, each with its `RelayState`. It is given the `StartResult`,
 * its `Navigation`, or the start's JSON body or its `navigation` member, as an
 * application's test holds it. A start that sent the browser nowhere, or a
 * message that is not an `AuthnRequest` with an `ID`, an `Issuer` and an
 * assertion consumer service URL, is a `LogicException` saying which.
 *
 * It checks no signature: what the identity provider would make of a signed
 * request is the package's own tests' to cover.
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

        /** The URL the request asks the response to be posted to. */
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
     * The request the navigation carries to the identity provider.
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
     * The XML of an encoded `SAMLRequest`: base64, and deflated as well when it
     * travelled in a URL.
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
     * The raw DEFLATE data inflated, or `false` when it is not DEFLATE data,
     * with the warning that says so kept from the test.
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
