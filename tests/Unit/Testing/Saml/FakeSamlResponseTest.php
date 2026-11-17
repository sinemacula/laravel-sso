<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Saml;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use Tests\Concerns\OutlinesSamlDocuments;

/**
 * Unit tests for the fake SAML identity provider's response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeSamlResponse::class)]
final class FakeSamlResponseTest extends TestCase
{
    use OutlinesSamlDocuments;

    /** @var string The service provider's assertion consumer service. */
    private const string ACS = 'https://sp.example.test/acs';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?string The service provider's encryption certificate, made once. */
    private static ?string $certificate = null;

    /**
     * The defaults are a successful response to the service provider, its
     * identifiers sharing one 16-hex-digit suffix and its instants relative to
     * now.
     *
     * @return void
     */
    public function testHoldsItsDefaults(): void
    {
        $options = FakeSamlResponse::defaults(FakeSamlIdentityProvider::ENTITY_ID, 'https://sp.example.test', self::ACS, CarbonImmutable::parse('2026-11-01T12:00:00Z'));

        self::assertMatchesRegularExpression('/^_response-[0-9a-f]{16}$/', $options['response_id']);

        $suffix = substr($options['response_id'], 10);

        self::assertSame(self::normalized(self::expectedDefaults($suffix)), self::normalized($options));
    }

    /**
     * Each response made has its own suffix.
     *
     * @return void
     */
    public function testEachResponseHasItsOwnIdentifiers(): void
    {
        $now = CarbonImmutable::parse('2026-11-01T12:00:00Z');

        self::assertNotSame(
            FakeSamlResponse::defaults(FakeSamlIdentityProvider::ENTITY_ID, 'https://sp.example.test', self::ACS, $now)['response_id'],
            FakeSamlResponse::defaults(FakeSamlIdentityProvider::ENTITY_ID, 'https://sp.example.test', self::ACS, $now)['response_id'],
        );
    }

    /**
     * `signed()` with no arguments signs the assertion alone, and
     * `encryptedFor()` defaults to RSA-OAEP key transport and AES-128-GCM.
     *
     * @return void
     */
    public function testSigningAndEncryptionDefaults(): void
    {
        $response = self::response()->signed(true, false)->signed();

        self::assertSame([false, true], [$response->option('sign_response'), $response->option('sign_assertion')]);
        self::assertSame(
            ['certificate' => 'pem', 'key_transport' => 'rsa-oaep-mgf1p', 'data' => 'aes128-gcm'],
            self::response()->encryptedFor('pem')->option('encrypt'),
        );
    }

    /**
     * Rows of `[response signed, assertion signed, outline]`.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: string}>
     */
    public static function provideSignings(): iterable
    {
        yield from [
            'the assertion' => [false, true, 'Response#_response{Assertion#_assertion{Signature}}'],
            'the response'  => [true, false, 'Response#_response{Signature,Assertion#_assertion}'],
            'both'          => [true, true, 'Response#_response{Signature,Assertion#_assertion{Signature}}'],
            'neither'       => [false, false, 'Response#_response{Assertion#_assertion}'],
        ];
    }

    /**
     * The response, the assertion, both or neither carry a signature, as asked.
     *
     * @param  bool  $response
     * @param  bool  $assertion
     * @param  string  $outline
     * @return void
     */
    #[DataProvider('provideSignings')]
    public function testSignsWhatItIsAskedTo(bool $response, bool $assertion, string $outline): void
    {
        self::assertSame($outline, self::outline(self::response()->signed($response, $assertion)->toXml()));
    }

    /**
     * An encrypted response carries an encrypted assertion in place of the
     * assertion, and a response without an assertion carries neither.
     *
     * @return void
     */
    public function testEncryptsOrLeavesOutTheAssertion(): void
    {
        self::assertSame('Response#_response{EncryptedAssertion}', self::outline(self::response()->encryptedFor(self::certificate())->toXml()));
        self::assertSame('Response#_response', self::outline(self::response()->with(['assertion' => false])->toXml()));
    }

    /**
     * A response signed by another key carries that key's certificate.
     *
     * @return void
     */
    public function testSignedByAnotherKeyCarriesItsCertificate(): void
    {
        $other = new FakeSamlIdentityProvider('https://other.example.test');
        $body  = preg_replace('/-----[^-]+-----|\s+/', '', $other->certificate());

        self::assertStringContainsString('<ds:X509Certificate>' . $body . '</ds:X509Certificate>', self::response()->signedBy($other->signer())->toXml());
    }

    /**
     * Rows of `[variant, outline]`: a variant wrapping the signed response, one
     * reusing the assertion's ID and one with an evil ID.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideWrappings(): iterable
    {
        yield from [
            'xsw1'           => ['xsw1', 'Response#_evil-response{Signature{Response#_response{Assertion#_assertion}},Assertion#_assertion}'],
            'same_id_before' => ['same_id_before', 'Response#_response{Assertion#_assertion,Assertion#_assertion{Signature}}'],
            'xsw3'           => ['xsw3', 'Response#_response{Assertion#_evil-assertion,Assertion#_assertion{Signature}}'],
        ];
    }

    /**
     * A wrapped response signs what the variant attacks and leaves the
     * assertion unencrypted, whatever was asked.
     *
     * @param  string  $variant
     * @param  string  $outline
     * @return void
     */
    #[DataProvider('provideWrappings')]
    public function testWrapsTheSignedPartInPlainText(string $variant, string $outline): void
    {
        $response = self::response()->signed(false, false)->encryptedFor(self::certificate())->wrapped($variant);

        self::assertSame($outline, self::outline($response->toXml()));
    }

    /**
     * A value XML cannot hold is refused rather than written.
     *
     * @return void
     */
    public function testRefusesAValueXmlCannotHold(): void
    {
        $previous = libxml_use_internal_errors(true);

        try {
            $this->expectExceptionObject(new \LogicException('The fake identity provider wrote XML it cannot parse.'));

            self::response()->with(['name_id' => "alice\x01"])->toXml();
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    }

    /**
     * The defaults expected for the suffix, every instant as a string.
     *
     * @param  string  $suffix
     * @return array<string, mixed>
     */
    private static function expectedDefaults(string $suffix): array
    {
        return [
            'response_id'             => '_response-' . $suffix,
            'assertion_id'            => '_assertion-' . $suffix,
            'issue_instant'           => '2026-11-01T12:00:00+00:00',
            'assertion_issue_instant' => '2026-11-01T12:00:00+00:00',
            'issuer'                  => FakeSamlIdentityProvider::ENTITY_ID,
            'assertion_issuer'        => FakeSamlIdentityProvider::ENTITY_ID,
            'destination'             => self::ACS,
            'in_response_to'          => null,
            'status'                  => 'urn:oasis:names:tc:SAML:2.0:status:Success',
            'sub_status'              => null,
            'status_message'          => null,
            'assertion'               => true,
            'subject'                 => true,
            'name_id'                 => 'alice',
            'name_id_format'          => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'name_qualifier'          => null,
            'sp_name_qualifier'       => null,
            'confirmations'           => [[
                'method'          => 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
                'data'            => true,
                'recipient'       => self::ACS,
                'not_before'      => null,
                'not_on_or_after' => '2026-11-01T12:05:00+00:00',
                'in_response_to'  => null,
            ]],
            'authn_statements' => [[
                'instant'                 => '2026-11-01T11:59:00+00:00',
                'session_index'           => '_session-' . $suffix,
                'session_not_on_or_after' => '2026-11-01T20:00:00+00:00',
                'class'                   => 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            ]],
            'conditions'            => true,
            'not_before'            => '2026-11-01T11:59:00+00:00',
            'not_on_or_after'       => '2026-11-01T12:05:00+00:00',
            'audiences'             => [['https://sp.example.test']],
            'one_time_use'          => 0,
            'proxy_restriction'     => 0,
            'unknown_conditions'    => 0,
            'attributes'            => ['email' => ['alice@example.test']],
            'attribute_name_format' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
            'advice'                => false,
            'sign_response'         => false,
            'sign_assertion'        => true,
            'algorithm'             => 'rsa-sha256',
            'digest'                => 'sha256',
            'comments'              => false,
            'uri'                   => null,
            'encrypt'               => null,
            'wrap'                  => null,
            'evil_name_id'          => 'mallory',
        ];
    }

    /**
     * The options with every instant as an ISO 8601 string and every keyed
     * array sorted by key, so a comparison ignores key order.
     *
     * @param  array<array-key, mixed>  $options
     * @return array<array-key, mixed>
     */
    private static function normalized(array $options): array
    {
        $normalized = array_map(
            static fn (mixed $value): mixed => match (true) {
                $value instanceof CarbonImmutable => $value->format('Y-m-d\TH:i:sP'),
                is_array($value)                  => self::normalized($value),
                default                           => $value,
            },
            $options,
        );

        if (!array_is_list($normalized)) {
            ksort($normalized);
        }

        return $normalized;
    }

    /**
     * A response from the provider with fixed identifiers.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private static function response(): FakeSamlResponse
    {
        self::$idp ??= new FakeSamlIdentityProvider;

        return self::$idp->response('https://sp.example.test', self::ACS)->with(['response_id' => '_response', 'assertion_id' => '_assertion']);
    }

    /**
     * The service provider's encryption certificate.
     *
     * @return string
     */
    private static function certificate(): string
    {
        return self::$certificate ??= FakeSamlIdentityProvider::keyPair('sp.example.test')[1];
    }
}
