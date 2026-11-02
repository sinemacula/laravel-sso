<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Endpoints\ConnectionEndpoints;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AuthnRequestWriter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\DumpsValues;
use Tests\TestCase;

/**
 * Feature tests for the SAML adapter's request writer and the value it answers
 * (SSO-5.3, SSO-5.10, SSO-9.8): the request valid against the protocol schema
 * for each binding, signed or not; the HTTP-Redirect message deflated raw at
 * level 9 and inflating back; the issue instant in UTC; `ForceAuthn` written
 * before the signature; the one refusal for anything the library refuses, with
 * no previous exception; and the outgoing request's redaction, its query
 * encoding and its refusal to be serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthnRequestWriter::class)]
#[CoversClass(OutgoingRequest::class)]
final class AuthnRequestWriterTest extends TestCase
{
    use DumpsValues;

    /** @var string The request id every request is written with. */
    private const string ID = '_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    /** @var string The `RelayState` every request carries: 43 base64url characters. */
    private const string STATE = 'Rs7-state_0123456789abcdefghijklmnopqrstuvw';

    /** @var string The identity provider's single sign-on URL. */
    private const string SSO_URL = 'https://idp.example.com/sso';

    /** @var string RSA-SHA256. */
    private const string RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    /** @var string Why anything the library refuses could not be written. */
    private const string UNWRITABLE = 'The SAML AuthnRequest could not be written: check the connection\'s settings and its current service provider signing key.';

    /** @var string The XML signature namespace. */
    private const string NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /** @var ?array{0: string, 1: string} The service provider's signing key and certificate, made once. */
    private static ?array $spKeys = null;

    /**
     * Rows of `[binding, signed]`: each binding, signed and not.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideBindings(): iterable
    {
        yield from [
            'redirect, unsigned' => ['http_redirect', false],
            'redirect, signed'   => ['http_redirect', true],
            'post, unsigned'     => ['http_post', false],
            'post, signed'       => ['http_post', true],
        ];
    }

    /**
     * The request is valid against the protocol schema for each binding, signed
     * or not, and carries an enveloped signature only when posted signed.
     *
     * @param  string  $binding
     * @param  bool  $signed
     * @return void
     */
    #[DataProvider('provideBindings')]
    public function testTheRequestIsSchemaValidForEachBinding(string $binding, bool $signed): void
    {
        $outgoing = $this->write(self::samlOptions($binding, ['urn:example:context']), true, $signed ? self::key() : null);
        $document = (new HardenedParser)->parse(self::xmlOf($outgoing), MessageKind::PROTOCOL, 1000000);
        $root     = $document->documentElement;

        self::assertNotNull($root);
        self::assertSame(['AuthnRequest', 'urn:oasis:names:tc:SAML:2.0:protocol', 'samlp'], [$root->localName, $root->namespaceURI, $root->prefix]);
        self::assertSame($signed && $binding === 'http_post' ? 1 : 0, $document->getElementsByTagNameNS(self::NS_DS, 'Signature')->length);
        self::assertSame([self::ID, self::ID, 'true'], [$outgoing->id, $root->getAttribute('ID'), $root->getAttribute('ForceAuthn')]);
    }

    /**
     * The HTTP-Redirect message is the XML deflated raw at level 9 and base64
     * encoded, and inflates back to the XML exactly. The single sign-on URL is
     * long and repetitive, so the deflated bytes are those of level 9 alone.
     *
     * @return void
     */
    public function testTheRedirectMessageIsDeflatedRawAtLevelNine(): void
    {
        $outgoing = $this->write(self::samlOptions('http_redirect', ssoUrl: self::SSO_URL . '?hint=' . self::words(1500)));
        $deflated = base64_decode($outgoing->fields()['SAMLRequest'], true);

        self::assertIsString($deflated);

        $xml = gzinflate($deflated);

        self::assertIsString($xml);
        self::assertSame($deflated, gzdeflate($xml, 9));
        self::assertStringStartsWith('<samlp:AuthnRequest ', $xml);
        self::assertStringNotContainsString('<?xml', $xml);
        self::assertSame($xml, self::xmlOf($outgoing));
    }

    /**
     * The posted message is the XML base64 encoded, never deflated.
     *
     * @return void
     */
    public function testThePostedMessageIsBase64AndNeverDeflated(): void
    {
        $outgoing = $this->write(self::samlOptions('http_post'));
        $xml      = base64_decode($outgoing->fields()['SAMLRequest'], true);

        self::assertIsString($xml);
        self::assertStringStartsWith('<samlp:AuthnRequest ', $xml);
        self::assertSame(['SAMLRequest', 'RelayState'], array_keys($outgoing->fields()));
        self::assertSame(self::STATE, $outgoing->fields()['RelayState']);
        self::assertSame(OutgoingRequest::HTTP_POST, $outgoing->binding);
        self::assertFalse($outgoing->isRedirect());
    }

    /**
     * The issue instant is the time given, in UTC, to the second.
     *
     * @return void
     */
    public function testTheIssueInstantIsInUtcToTheSecond(): void
    {
        $outgoing = $this->write(self::samlOptions('http_redirect'), issuedAt: CarbonImmutable::parse('2026-11-01T11:30:00.987654+02:00'));

        self::assertSame('2026-11-01T09:30:00Z', self::rootOf(self::documentOf($outgoing))->getAttribute('IssueInstant'));
    }

    /**
     * `ForceAuthn` is absent unless asked for, and a posted signature covers
     * it.
     *
     * @return void
     */
    public function testForceAuthnIsWrittenBeforeTheSignature(): void
    {
        $plain  = self::rootOf(self::documentOf($this->write(self::samlOptions('http_post'))));
        $forced = self::documentOf($this->write(self::samlOptions('http_post'), true, self::key()));
        $root   = self::rootOf($forced);

        self::assertFalse($plain->hasAttribute('ForceAuthn'));
        self::assertSame('true', $root->getAttribute('ForceAuthn'));

        $signature = $root->getElementsByTagNameNS(self::NS_DS, 'Signature')->item(0);
        $digest    = $root->getElementsByTagNameNS(self::NS_DS, 'DigestValue')->item(0)?->textContent;

        self::assertNotNull($signature);
        self::assertNotNull($digest);

        $root->removeChild($signature);

        self::assertSame($digest, base64_encode(hash('sha256', (string) $root->C14N(true, false), true)));
    }

    /**
     * A connection with no single sign-on URL cannot be written to.
     *
     * @return void
     */
    public function testARequestNeedsTheSingleSignOnUrl(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('An AuthnRequest is sent to the connection\'s single sign-on URL, which it has none of.');

        $this->write(self::samlOptions('http_redirect', ssoUrl: null));
    }

    /**
     * Rows of `[options, key]`: what the library refuses, or a signed request
     * with no algorithm to sign with.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options, 1: \Closure(): ?\SineMacula\Laravel\Sso\Secrets\Secret}>
     */
    public static function provideUnwritable(): iterable
    {
        yield from [
            'no signature algorithm'   => [static fn (): Saml2Options => self::samlOptions('http_redirect', algorithms: []), static fn (): Secret => self::key()],
            'a certificate, not a key' => [static fn (): Saml2Options => self::samlOptions('http_post'), static fn (): Secret => new Secret(self::keys()[1])],
            'a key that is not PEM'    => [static fn (): Saml2Options => self::samlOptions('http_redirect'), static fn (): Secret => new Secret('not a key')],
            'a context that is no URI' => [static fn (): Saml2Options => self::samlOptions('http_redirect', ['not a uri']), static fn (): ?Secret => null],
        ];
    }

    /**
     * Anything the library refuses is the one `LogicException`, with no
     * previous exception and none of the request in its message.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  \Closure(): ?\SineMacula\Laravel\Sso\Secrets\Secret  $key
     * @return void
     */
    #[DataProvider('provideUnwritable')]
    public function testAnythingTheLibraryRefusesIsOneLogicException(\Closure $options, \Closure $key): void
    {
        try {
            $this->write($options(), false, $key());
            self::fail('The request was written.');
        } catch (\LogicException $exception) {
            self::assertSame(self::UNWRITABLE, $exception->getMessage());
            self::assertNull($exception->getPrevious());
            self::assertStringNotContainsString(self::STATE, (string) $exception);
            self::assertStringNotContainsString('not a key', (string) $exception);
        }
    }

    /**
     * The outgoing request shows its id, its binding and its field names, never
     * a field's value, in every dump and in JSON.
     *
     * @return void
     */
    public function testTheOutgoingRequestRedactsItsFields(): void
    {
        $outgoing = $this->write(self::samlOptions('http_redirect'), false, self::key());
        $message  = $outgoing->fields()['SAMLRequest'];
        $redacted = [
            'id'      => self::ID,
            'binding' => OutgoingRequest::HTTP_REDIRECT,
            'fields'  => ['SAMLRequest' => '[redacted]', 'RelayState' => '[redacted]', 'SigAlg' => '[redacted]', 'Signature' => '[redacted]'],
        ];

        self::assertSame($redacted, $outgoing->__debugInfo());
        self::assertSame($redacted, $outgoing->jsonSerialize());
        self::assertSame((string) json_encode($redacted), json_encode($outgoing));

        foreach (self::dumps($outgoing) as $by => $dump) {
            self::assertStringNotContainsString(self::STATE, $dump, $by);
            self::assertStringNotContainsString(substr($message, 0, 24), $dump, $by);
            self::assertStringNotContainsString($outgoing->fields()['Signature'], $dump, $by);
        }
    }

    /**
     * The outgoing request refuses to be serialised.
     *
     * @return void
     */
    public function testTheOutgoingRequestRefusesSerialisation(): void
    {
        $outgoing = new OutgoingRequest(self::ID, OutgoingRequest::HTTP_POST, ['SAMLRequest' => 'x', 'RelayState' => self::STATE]);

        $this->expectExceptionObject(new \LogicException(sprintf('A %s cannot be serialised.', OutgoingRequest::class)));

        serialize($outgoing);
    }

    /**
     * The outgoing request refuses to be unserialised.
     *
     * @return void
     */
    public function testTheOutgoingRequestRefusesUnserialisation(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('A %s cannot be unserialised.', OutgoingRequest::class));

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(OutgoingRequest::class), OutgoingRequest::class));
    }

    /**
     * The query string percent-encodes each value (RFC 3986) and keeps the
     * fields' order; a redirect is a redirect.
     *
     * @return void
     */
    public function testTheQueryEncodesEachValueInOrder(): void
    {
        $outgoing = new OutgoingRequest(self::ID, OutgoingRequest::HTTP_REDIRECT, ['B' => 'a b+/=?&', 'A' => '~-._', 'C' => '']);

        self::assertSame('B=a%20b%2B%2F%3D%3F%26&A=~-._&C=', $outgoing->query());
        self::assertSame($outgoing->query(), OutgoingRequest::encode($outgoing->fields()));
        self::assertSame('', OutgoingRequest::encode([]));
        self::assertTrue($outgoing->isRedirect());
        self::assertSame(['B', 'A', 'C'], array_keys($outgoing->fields()));
    }

    /**
     * An outgoing request is sent by the HTTP-Redirect or the HTTP-POST
     * binding, and no other.
     *
     * @return void
     */
    public function testAnOutgoingRequestIsSentByARequestBinding(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An AuthnRequest is sent by the HTTP-Redirect or the HTTP-POST binding.');

        new OutgoingRequest(self::ID, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact', []);
    }

    /**
     * Write a request with the options, at 09:30 UTC unless told otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  bool  $forceAuthn
     * @param  ?\SineMacula\Laravel\Sso\Secrets\Secret  $key
     * @param  ?\Carbon\CarbonImmutable  $issuedAt
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest
     */
    private function write(Saml2Options $options, bool $forceAuthn = false, ?Secret $key = null, ?CarbonImmutable $issuedAt = null): OutgoingRequest
    {
        $endpoints = new ConnectionEndpoints(
            'https://api.example.com/auth/sso/connections/c1/assertions',
            'https://api.example.com/auth/sso/connections/c1/callback',
            'https://api.example.com/auth/sso/connections/c1/metadata',
            'https://api.example.com/auth/sso/connections/c1/metadata',
        );

        $issuedAt ??= CarbonImmutable::parse('2026-11-01T09:30:00Z');

        return (new AuthnRequestWriter)->write(self::ID, $issuedAt, $endpoints, $options, $forceAuthn, new Secret(self::STATE), $key);
    }

    /**
     * Options for the binding, with the requested contexts and signature
     * algorithms given.
     *
     * @param  string  $binding
     * @param  list<string>  $contexts
     * @param  list<string>  $algorithms
     * @param  ?string  $ssoUrl
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options
     */
    private static function samlOptions(string $binding, array $contexts = [], array $algorithms = [self::RSA_SHA256], ?string $ssoUrl = self::SSO_URL): Saml2Options
    {
        return new Saml2Options(
            'https://idp.example.com/entity',
            $ssoUrl,
            $binding,
            'name_id',
            null,
            'persistent',
            [],
            ['signature_algorithms' => $algorithms, 'requested_authn_context' => $contexts],
            null,
            null,
            null,
        );
    }

    /**
     * A deterministic run of the words: each of eight words chosen by the CRC
     * of its index, joined by `-`, with `.` after every thirteenth.
     *
     * @param  int  $count
     * @return string
     */
    private static function words(int $count): string
    {
        $words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta'];
        $run   = '';

        for ($index = 0; $index < $count; $index++) {
            $run .= $words[crc32((string) $index) % 8] . ($index % 13 === 0 ? '.' : '-');
        }

        return $run;
    }

    /**
     * The service provider's private signing key.
     *
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     */
    private static function key(): Secret
    {
        return new Secret(self::keys()[0]);
    }

    /**
     * The service provider's signing key and certificate, made once.
     *
     * @return array{0: string, 1: string}
     */
    private static function keys(): array
    {
        return self::$spKeys ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }

    /**
     * The request's XML, inflated for a redirect and decoded for a post.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest  $outgoing
     * @return string
     */
    private static function xmlOf(OutgoingRequest $outgoing): string
    {
        $decoded = (string) base64_decode($outgoing->fields()['SAMLRequest'], true);

        return $outgoing->isRedirect() ? (string) gzinflate($decoded) : $decoded;
    }

    /**
     * The request's XML, parsed.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\OutgoingRequest  $outgoing
     * @return \DOMDocument
     */
    private static function documentOf(OutgoingRequest $outgoing): \DOMDocument
    {
        $document = new \DOMDocument;

        self::assertTrue($document->loadXML(self::xmlOf($outgoing), LIBXML_NONET));

        return $document;
    }

    /**
     * The document's root element.
     *
     * @param  \DOMDocument  $document
     * @return \DOMElement
     */
    private static function rootOf(\DOMDocument $document): \DOMElement
    {
        $root = $document->documentElement;

        self::assertNotNull($root);

        return $root;
    }
}
