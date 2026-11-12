<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Saml;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Protocols\Navigation;
use SineMacula\Laravel\Sso\Testing\Navigations;
use SineMacula\Laravel\Sso\Testing\Saml\FakeAuthnRequest;
use SineMacula\Laravel\Sso\Testing\Saml\XmlDocument;

/**
 * Unit tests for the `AuthnRequest` the fake identity provider receives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeAuthnRequest::class)]
#[CoversClass(XmlDocument::class)]
#[CoversClass(Navigations::class)]
final class FakeAuthnRequestTest extends TestCase
{
    /** @var string The single sign-on URL the requests go to. */
    private const string SSO_URL = 'https://idp.example.test/saml/sso';

    /** @var string A request, with the attributes it is given in place of `{attributes}`. */
    private const string REQUEST = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        . 'Version="2.0" IssueInstant="2026-11-01T09:30:00Z" {attributes}><saml:Issuer> https://sp.example.test/metadata </saml:Issuer></samlp:AuthnRequest>';

    /** @var string The attributes of a valid request. */
    private const string ATTRIBUTES = 'ID="_request-1" Destination="https://idp.example.test/saml/sso" AssertionConsumerServiceURL="https://sp.example.test/acs"';

    /**
     * A request sent by HTTP-Redirect is read from the URL's query, inflated,
     * with its `RelayState`; every part of it is as the XML says.
     *
     * @return void
     */
    public function testReadsARedirect(): void
    {
        $xml     = self::xml(self::ATTRIBUTES . ' ForceAuthn="true"');
        $request = FakeAuthnRequest::fromNavigation(Navigation::redirect(self::redirectUrl(base64_encode((string) gzdeflate($xml)), 'relay-1')));

        self::assertSame(
            ['_request-1', 'https://sp.example.test/metadata', 'https://sp.example.test/acs', self::SSO_URL, true, 'relay-1', $xml],
            [$request->id, $request->issuer, $request->assertionConsumerService, $request->destination, $request->forceAuthn, $request->relayState, $request->xml],
        );
    }

    /**
     * A request sent by HTTP-POST is read from the form's fields, base64 alone,
     * with its `RelayState`, whatever the URL's query says.
     *
     * @return void
     */
    public function testReadsAPost(): void
    {
        $xml        = self::xml(self::ATTRIBUTES);
        $navigation = Navigation::post(self::SSO_URL . '?SAMLRequest=ignored', ['SAMLRequest' => base64_encode($xml), 'RelayState' => 'relay-2']);
        $request    = FakeAuthnRequest::fromNavigation($navigation);

        self::assertSame(['_request-1', 'relay-2', false, $xml], [$request->id, $request->relayState, $request->forceAuthn, $request->xml]);
    }

    /**
     * Rows of `[navigation]`: the same redirect as a start's result, as its
     * JSON body, and as that body's `navigation` member.
     *
     * @return iterable<string, array{0: array<array-key, mixed>|\SineMacula\Laravel\Sso\Flows\StartResult}>
     *
     * @throws \Random\RandomException
     */
    public static function provideForms(): iterable
    {
        $navigation = Navigation::redirect(self::redirectUrl(base64_encode((string) gzdeflate(self::xml(self::ATTRIBUTES))), 'relay-3'));
        $started    = StartResult::started(RequestReference::generate(), $navigation);

        yield 'a start result' => [$started];
        yield 'the start body' => [$started->body()];
        yield 'its navigation' => [$navigation->jsonSerialize()];
    }

    /**
     * The request is read from each form a test holds a start in.
     *
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Sso\Flows\StartResult  $navigation
     * @return void
     */
    #[DataProvider('provideForms')]
    public function testReadsEachFormOfAStart(array|StartResult $navigation): void
    {
        $request = FakeAuthnRequest::fromNavigation($navigation);

        self::assertSame(['_request-1', 'relay-3'], [$request->id, $request->relayState]);
    }

    /**
     * Rows of `[the ForceAuthn attribute, whether it forces authentication]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideForceAuthn(): iterable
    {
        yield 'true' => [' ForceAuthn="true"', true];
        yield 'one' => [' ForceAuthn="1"', true];
        yield 'false' => [' ForceAuthn="false"', false];
        yield 'absent' => ['', false];
    }

    /**
     * Only `true` and `1` force authentication; a request with no destination
     * or relay state has none.
     *
     * @param  string  $attribute
     * @param  bool  $forced
     * @return void
     */
    #[DataProvider('provideForceAuthn')]
    public function testForcesAuthenticationOnlyWhenItSaysSo(string $attribute, bool $forced): void
    {
        $xml     = self::xml('ID="_request-1" AssertionConsumerServiceURL="https://sp.example.test/acs"' . $attribute);
        $request = FakeAuthnRequest::fromNavigation(Navigation::post(self::SSO_URL, ['SAMLRequest' => base64_encode($xml)]));

        self::assertSame([$forced, null, null], [$request->forceAuthn, $request->destination, $request->relayState]);
    }

    /**
     * Rows of `[navigation, message]`: what cannot be read, and why.
     *
     * @return iterable<string, array{0: array<array-key, mixed>|\SineMacula\Laravel\Sso\Flows\StartResult|\SineMacula\Laravel\Sso\Protocols\Navigation, 1: string}>
     */
    public static function provideUnreadable(): iterable
    {
        $post = static fn (string $xml): Navigation => Navigation::post(self::SSO_URL, ['SAMLRequest' => base64_encode($xml)]);

        yield 'a refused start' => [StartResult::refused(FailureReason::CONNECTION_UNAVAILABLE), 'The flow did not start: it was refused with [connection_unavailable].'];
        yield 'no request' => [Navigation::redirect(self::SSO_URL . '?RelayState=relay'), 'The navigation carries no SAMLRequest.'];
        yield 'an array request' => [Navigation::redirect(self::SSO_URL . '?SAMLRequest[]=a'), 'The navigation carries no SAMLRequest.'];
        yield 'an empty body' => [[], 'The navigation carries no SAMLRequest.'];
        yield 'a body of other types' => [['url' => 1, 'fields' => 'SAMLRequest'], 'The navigation carries no SAMLRequest.'];
        yield 'not base64 in a URL' => [Navigation::redirect(self::redirectUrl('*', null)), 'The SAMLRequest is not deflated and base64 encoded.'];
        yield 'not deflated' => [Navigation::redirect(self::redirectUrl(base64_encode("\x07 not DEFLATE data"), null)), 'The SAMLRequest is not deflated and base64 encoded.'];
        yield 'not base64 in a form' => [Navigation::post(self::SSO_URL, ['SAMLRequest' => '*']), 'The SAMLRequest is not base64 encoded.'];
        yield 'empty' => [$post(''), 'The SAMLRequest is not an XML document without a document type.'];
        yield 'not XML' => [$post('not xml'), 'The SAMLRequest is not an XML document without a document type.'];
        yield 'a document type' => [$post('<!DOCTYPE a><a/>'), 'The SAMLRequest is not an XML document without a document type.'];
        yield 'another element' => [$post('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'), 'The SAMLRequest is not an AuthnRequest.'];
        yield 'another namespace' => [$post('<AuthnRequest ID="_request-1"/>'), 'The SAMLRequest is not an AuthnRequest.'];
        yield 'no ID' => [$post(self::xml('AssertionConsumerServiceURL="https://sp.example.test/acs"')), 'The AuthnRequest has no ID.'];
        yield 'no ACS' => [$post(self::xml('ID="_request-1"')), 'The AuthnRequest has no AssertionConsumerServiceURL.'];
        yield 'no issuer' => [$post((string) preg_replace('#<saml:Issuer>.*</saml:Issuer>#', '', self::xml(self::ATTRIBUTES))), 'The AuthnRequest has no Issuer.'];
        yield 'an empty issuer' => [$post(str_replace(' https://sp.example.test/metadata ', ' ', self::xml(self::ATTRIBUTES))), 'The AuthnRequest has no Issuer.'];
    }

    /**
     * Each refused with a `LogicException` saying why.
     *
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Sso\Flows\StartResult|\SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideUnreadable')]
    public function testRefusesWhatItCannotRead(array|Navigation|StartResult $navigation, string $message): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage($message);

        FakeAuthnRequest::fromNavigation($navigation);
    }

    /**
     * Reading leaves no libxml error behind and restores the error handling it
     * found, so the test's next XML is unaffected.
     *
     * @return void
     */
    public function testLeavesLibxmlAsItFoundIt(): void
    {
        $previous = libxml_use_internal_errors(false);

        try {
            FakeAuthnRequest::fromNavigation(Navigation::post(self::SSO_URL, ['SAMLRequest' => base64_encode('<broken')]));
            self::fail('A broken document was read.');
        } catch (\LogicException $exception) {
            self::assertSame('The SAMLRequest is not an XML document without a document type.', $exception->getMessage());
        }

        $errors = libxml_get_errors();

        self::assertFalse(libxml_use_internal_errors($previous));
        self::assertSame([], $errors);
    }

    /**
     * The request's XML with the attributes given.
     *
     * @param  string  $attributes
     * @return string
     */
    private static function xml(string $attributes): string
    {
        return str_replace('{attributes}', $attributes, self::REQUEST);
    }

    /**
     * An HTTP-Redirect URL carrying the encoded request and the relay state.
     *
     * @param  string  $encoded
     * @param  ?string  $relayState
     * @return string
     */
    private static function redirectUrl(string $encoded, ?string $relayState): string
    {
        return self::SSO_URL . '?' . http_build_query(array_filter(['SAMLRequest' => $encoded, 'RelayState' => $relayState], is_string(...)));
    }
}
