<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AssertionDecryptor;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AssertionMapper;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\PinnedVerifier;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\ResponseReader;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlAdapter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ReadResult;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Limits;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Secrets\Secret;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\AssertionEncryptor;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use SineMacula\Laravel\Sso\Testing\Saml\ResponseWriter;
use SineMacula\Laravel\Sso\Testing\Saml\SignatureWrapping;
use Tests\TestCase;

/**
 * Feature tests for the SAML adapter (SSO-6.1 to SSO-6.3, SSO-6.7, SSO-6.8,
 * SSO-6.11), with responses from the fake identity provider: the caps, each at,
 * under and over its limit; the envelope read before validation; every value of
 * a verified response and assertion; the four profiles; the signature policy
 * and the pinned certificates; every wrapping variant; the structure rules; and
 * decryption, with its one indistinguishable failure and its ordering.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-import-type ResponseOptions from \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
 */
#[CoversClass(SamlAdapter::class)]
#[CoversClass(HardenedParser::class)]
#[CoversClass(ResponseReader::class)]
#[CoversClass(PinnedVerifier::class)]
#[CoversClass(AssertionDecryptor::class)]
#[CoversClass(AssertionMapper::class)]
final class SamlAdapterTest extends TestCase
{
    /** @var string The service provider's entity id. */
    private const string SP = 'https://sp.example.test/saml';

    /** @var string The assertion consumer service URL. */
    private const string ACS = 'https://sp.example.test/saml/acs';

    /** @var string The request the responses answer. */
    private const string REQUEST_ID = '_request-1';

    /** @var string AES-128-CBC. */
    private const string AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The trusted identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider An identity provider the policy does not trust, made once. */
    private static ?FakeSamlIdentityProvider $attacker = null;

    /** @var ?array{0: string, 1: string} The service provider's encryption key and certificate, made once. */
    private static ?array $spKeys = null;

    /** @var int How many times the policy was asked for its decryption keys. */
    private int $keysAsked = 0;

    /**
     * The envelope of a response signed only in its assertion is read as
     * received, and the response is solicited.
     *
     * @return void
     */
    public function testReadsTheEnvelope(): void
    {
        $read = $this->readExample();

        self::assertSame(
            ['solicited', '_response-1', '2026-11-01T12:00:00+00:00', false],
            [$read->profile()->value, $read->id(), $read->issueInstant()->toIso8601String(), $read->isSigned()],
        );
        self::assertSame(
            [FakeSamlIdentityProvider::ENTITY_ID, null, self::ACS, self::REQUEST_ID],
            [$read->issuer()?->value(), $read->issuer()?->format(), $read->destination(), $read->inResponseTo()],
        );
        self::assertSame(
            [FakeSamlResponse::SUCCESS, null, null, true],
            [$read->status()->code(), $read->status()->subCode(), $read->status()->message(), $read->status()->isSuccess()],
        );
    }

    /**
     * The assertion's own values are read from its verified element.
     *
     * @return void
     */
    public function testReadsTheAssertion(): void
    {
        $assertion = self::assertionOf($this->readExample());

        self::assertSame(
            ['_assertion-1', FakeSamlIdentityProvider::ENTITY_ID, '2026-11-01T12:00:00+00:00', true, false],
            [$assertion->id(), $assertion->issuer()->value(), $assertion->issueInstant()->toIso8601String(), $assertion->isSigned(), $assertion->isEncrypted()],
        );
        self::assertSame([0, [], false], [$assertion->encryptedAttributes(), $assertion->otherStatements(), $assertion->hasAdvice()]);
    }

    /**
     * The subject's NameID, with every qualifier, and its one bearer
     * confirmation are read whole.
     *
     * @return void
     */
    public function testReadsTheSubject(): void
    {
        $subject = self::assertionOf($this->readExample())->subject();

        self::assertNotNull($subject);

        $nameId = $subject->nameId();

        self::assertNotNull($nameId);
        self::assertSame(IdentifierKind::NAME_ID, $subject->kind());
        self::assertSame(
            ['alice', FakeSamlResponse::PERSISTENT, 'https://idp.example.test/saml', self::SP, null],
            [$nameId->value(), $nameId->format(), $nameId->nameQualifier(), $nameId->spNameQualifier(), $nameId->spProvidedId()],
        );
        self::assertCount(1, $subject->confirmations());

        $confirmation = $subject->confirmations()[0];

        self::assertSame([FakeSamlResponse::BEARER, true, true, null, '2026-11-01T12:05:00+00:00', self::ACS, self::REQUEST_ID, null], [
            $confirmation->method(), $confirmation->isBearer(), $confirmation->hasData(), $confirmation->notBefore(),
            $confirmation->notOnOrAfter()?->toIso8601String(), $confirmation->recipient(), $confirmation->inResponseTo(), $confirmation->address(),
        ]);
    }

    /**
     * The conditions, the authentication statement and every attribute are read
     * whole.
     *
     * @return void
     */
    public function testReadsTheConditionsStatementAndAttributes(): void
    {
        $assertion  = self::assertionOf($this->readExample());
        $conditions = $assertion->conditions();

        self::assertNotNull($conditions);
        self::assertSame(['2026-11-01T11:59:00+00:00', '2026-11-01T12:05:00+00:00', [[self::SP]], 0, 0, []], [
            $conditions->notBefore()?->toIso8601String(), $conditions->notOnOrAfter()?->toIso8601String(), $conditions->audienceRestrictions(),
            $conditions->oneTimeUse(), $conditions->proxyRestrictions(), $conditions->otherConditions(),
        ]);
        self::assertCount(1, $assertion->authnStatements());

        $statement = $assertion->authnStatements()[0];

        self::assertSame(['2026-11-01T11:59:00+00:00', '_session-1', '2026-11-01T20:00:00+00:00', FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT], [
            $statement->authnInstant()->toIso8601String(), $statement->sessionIndex(), $statement->sessionNotOnOrAfter()?->toIso8601String(), $statement->contextClassRef(),
        ]);
        self::assertSame([
            ['email', 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', null, ['alice@example.test']],
            ['groups', 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', null, ['admins', 'staff']],
        ], array_map(static fn ($attribute): array => [$attribute->name(), $attribute->nameFormat(), $attribute->friendlyName(), $attribute->values()], $assertion->attributes()));
    }

    /**
     * A response signed in its envelope alone is read from the verified
     * response: the envelope is signed content, the assertion is not signed
     * itself.
     *
     * @return void
     */
    public function testAResponseSignedInItsEnvelopeIsReadFromTheVerifiedResponse(): void
    {
        $read = $this->read(self::response()->signed(true, false)->encoded())->response;

        self::assertSame([true, false, 'alice'], [$read?->isSigned(), $read?->assertion()?->isSigned(), $read?->assertion()?->subject()?->nameId()?->value()]);
    }

    /**
     * A response signed in both places verifies both signatures.
     *
     * @return void
     */
    public function testBothSignaturesAreVerified(): void
    {
        $read = $this->read(self::response()->signed(true, true)->encoded())->response;

        self::assertSame([true, true], [$read?->isSigned(), $read?->assertion()?->isSigned()]);
        self::assertSame(['signature_invalid', 'signature'], $this->refusal(self::response()->signed(true, true)->signedBy(self::attacker()->signer())->encoded()));
    }

    /**
     * A response with no signature covering its assertion is refused, and one
     * signed by a key the policy does not trust, its certificate in the
     * message, is refused too.
     *
     * @return void
     */
    public function testAnAssertionCoveredByNoTrustedSignatureIsRefused(): void
    {
        self::assertSame(['signature_invalid', 'unsigned'], $this->refusal(self::response()->signed(false, false)->encoded()));
        self::assertSame(['signature_invalid', 'signature'], $this->refusal(self::response()->signedBy(self::attacker()->signer())->encoded()));
        self::assertSame(['signature_invalid', 'signature'], $this->refusal(self::response()->signed(true, false)->signedBy(self::attacker()->signer())->encoded()));
    }

    /**
     * A signature verifies with any of the trusted certificates, in any order.
     *
     * @return void
     */
    public function testASignatureVerifiesWithAnyTrustedCertificate(): void
    {
        $encoded = self::response()->encoded();

        self::assertTrue($this->read($encoded, ['certificates' => [self::attacker()->certificate(), self::idp()->certificate()]])->isRead());
        self::assertTrue($this->read($encoded, ['certificates' => [self::idp()->certificate(), self::attacker()->certificate()]])->isRead());
        self::assertSame(['signature_invalid', 'signature'], $this->refusal($encoded, ['certificates' => ['not a certificate', self::attacker()->certificate()]]));
        self::assertSame(['signature_invalid', 'signature'], $this->refusal($encoded, ['certificates' => []]));
    }

    /**
     * Rows of `[options, allowed]`: a response signed with the options, and
     * whether the default policy admits its signature.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideSignaturePolicies(): iterable
    {
        yield from [
            'rsa-sha256 and sha256'          => [['algorithm' => 'rsa-sha256', 'digest' => 'sha256'], true],
            'rsa-sha512 and sha384'          => [['algorithm' => 'rsa-sha512', 'digest' => 'sha384'], true],
            'rsa-sha384 and sha512'          => [['algorithm' => 'rsa-sha384', 'digest' => 'sha512'], true],
            'rsa-sha1'                       => [['algorithm' => 'rsa-sha1', 'digest' => 'sha256'], false],
            'a sha-1 digest'                 => [['algorithm' => 'rsa-sha256', 'digest' => 'sha1'], false],
            'with-comments canonicalisation' => [['comments' => true], false],
        ];
    }

    /**
     * The signature method and the digest must be allowed, and the
     * canonicalisation must exclude comments, before anything is verified.
     *
     * @param  array<string, mixed>  $options
     * @param  bool  $allowed
     * @return void
     */
    #[DataProvider('provideSignaturePolicies')]
    public function testTheSignaturePolicyIsHeldBeforeVerifying(array $options, bool $allowed): void
    {
        $result = $this->read(self::response()->with($options)->encoded());

        self::assertSame($allowed, $result->isRead());
        self::assertSame($allowed ? null : 'signature_policy', $result->detail);
    }

    /**
     * An algorithm the library verifies is refused when the connection does not
     * list it, and admitted when it does.
     *
     * @return void
     */
    public function testTheConnectionsAllowListLimitsTheSignatureMethod(): void
    {
        $encoded = self::response()->with(['algorithm' => 'rsa-sha512'])->encoded();

        self::assertSame(['signature_invalid', 'signature_policy'], $this->refusal($encoded, ['algorithms' => ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']]));
        self::assertTrue($this->read($encoded, ['algorithms' => ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha512']])->isRead());
        self::assertSame(['signature_invalid', 'signature_policy'], $this->refusal(self::response()->encoded(), ['algorithms' => ['http://www.w3.org/2000/09/xmldsig#rsa-sha1']]));
    }

    /**
     * A reference to the whole document is refused as a structure the library
     * will not read; a signature over another element is refused by policy.
     *
     * @return void
     */
    public function testAReferenceMustNameTheSignedElementItself(): void
    {
        self::assertSame(['response_invalid', 'structure'], $this->refusal(self::response()->signed(true, false)->with(['uri' => ''])->encoded()));
        self::assertSame(['signature_invalid', 'signature_policy'], $this->refusal(self::response()->signed(true, false)->with(['uri' => '#_elsewhere'])->encoded()));
    }

    /**
     * Rows of `[variant]`: each signature wrapping variant.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideWrappingVariants(): iterable
    {
        foreach (SignatureWrapping::VARIANTS as $variant) {
            yield $variant => [$variant];
        }
    }

    /**
     * Every signature wrapping variant is refused, and never yields the evil
     * subject.
     *
     * @param  string  $variant
     * @return void
     */
    #[DataProvider('provideWrappingVariants')]
    public function testEverySignatureWrappingVariantIsRefused(string $variant): void
    {
        $result = $this->read(self::response()->wrapped($variant)->encoded());

        self::assertFalse($result->isRead());
        self::assertContains($result->reason?->value, ['response_invalid', 'signature_invalid']);
    }

    /**
     * Rows of `[changes, profile]`: a response, and the profile it falls under.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideProfiles(): iterable
    {
        yield from [
            'an InResponseTo on the response and confirmation' => [['in_response_to' => self::REQUEST_ID], 'solicited'],
            'an InResponseTo on the confirmation alone'        => [['confirmations' => [self::answeringConfirmation()]], 'solicited'],
            'no InResponseTo anywhere'                         => [[], 'unsolicited'],
        ];
    }

    /**
     * A successful response with an `InResponseTo` anywhere is solicited, and
     * one with none unsolicited.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $profile
     * @return void
     */
    #[DataProvider('provideProfiles')]
    public function testASuccessfulResponseIsSolicitedOrUnsolicited(array $changes, string $profile): void
    {
        self::assertSame($profile, $this->read(self::response()->inResponseTo(null)->with($changes)->encoded())->response?->profile()->value);
    }

    /**
     * An encrypted assertion's `InResponseTo`, seen only once it is decrypted,
     * makes the response solicited.
     *
     * @return void
     */
    public function testAnInResponseToInsideAnEncryptedAssertionMakesItSolicited(): void
    {
        $encrypted = self::response()->inResponseTo(null)->with(['confirmations' => [self::answeringConfirmation()]])->encryptedFor(self::spKeys()[1]);

        self::assertSame('solicited', $this->read($encrypted->encoded())->response?->profile()->value);
        self::assertSame('unsolicited', $this->read(self::response()->inResponseTo(null)->encryptedFor(self::spKeys()[1])->encoded())->response?->profile()->value);
    }

    /**
     * An unsuccessful response reads no assertion, keeps the provider's status
     * message for the sanitiser, and still verifies every signature present.
     *
     * @return void
     */
    public function testAnUnsuccessfulResponseReadsNoAssertionButVerifiesItsSignatures(): void
    {
        $failed = self::response()->with([
            'status'         => 'urn:oasis:names:tc:SAML:2.0:status:Responder',
            'sub_status'     => 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
            'status_message' => 'The user cancelled',
        ]);

        $read = $this->read($failed->encoded())->response;

        self::assertNotNull($read);

        $status = $read->status();

        self::assertSame(['unsuccessful', null, false], [$read->profile()->value, $read->assertion(), $status->isSuccess()]);
        self::assertSame('urn:oasis:names:tc:SAML:2.0:status:Responder', $status->code());
        self::assertSame(['urn:oasis:names:tc:SAML:2.0:status:AuthnFailed', 'The user cancelled'], [$status->subCode(), $status->message()]);
        self::assertSame(['signature_invalid', 'signature'], $this->refusal($failed->signedBy(self::attacker()->signer())->encoded()));
        self::assertTrue($this->read($failed->with(['assertion' => false])->signed(false, false)->encoded())->isRead());
    }

    /**
     * A successful response with no assertion, and a document that is not a
     * response, are refused.
     *
     * @return void
     */
    public function testAResponseMustBeAResponseWithOneAssertion(): void
    {
        $empty  = (new ResponseWriter)->response(self::responseOptions(), '');
        $logout = '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout" Version="2.0" IssueInstant="2026-11-01T12:00:00Z">'
            . '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>';

        self::assertSame(['response_invalid', 'assertion_count'], $this->refusal(base64_encode($empty)));
        self::assertSame(['response_invalid', 'not_a_response'], $this->refusal(base64_encode($logout)));
    }

    /**
     * Two elements anywhere that share an identity attribute's value are
     * refused, even where the schema does not look.
     *
     * @return void
     */
    public function testARepeatedIdentityAttributeAnywhereIsRefused(): void
    {
        $xml = str_replace(
            '<samlp:Status>',
            '<samlp:Extensions><ex:Note xmlns:ex="urn:example:extensions" ID="_assertion-twice"/></samlp:Extensions><samlp:Status>',
            self::response()->with(['assertion_id' => '_assertion-twice'])->toXml(),
        );

        self::assertSame(['response_invalid', 'duplicate_id'], $this->refusal(base64_encode($xml)));
    }

    /**
     * A signature anywhere but the response's own or its assertion's is
     * refused.
     *
     * @return void
     */
    public function testASignatureOutOfPlaceIsRefused(): void
    {
        $signed    = self::response()->signed(false, true)->toXml();
        $start     = (int) strpos($signed, '<ds:Signature');
        $signature = substr($signed, $start, (int) strpos($signed, '</ds:Signature>') + strlen('</ds:Signature>') - $start);
        $moved     = str_replace('<samlp:Status>', '<samlp:Extensions>' . $signature . '</samlp:Extensions><samlp:Status>', self::response()->signed(true, false)->toXml());

        self::assertSame(['response_invalid', 'signature_location'], $this->refusal(base64_encode($moved)));
    }

    /**
     * Rows of `[length, read]`: an encoded value of the length around the
     * default cap, and whether it reaches the parser.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideEncodedLengths(): iterable
    {
        yield from [
            'one under the cap' => [Saml2Limits::DEFAULT_MAX_RESPONSE_BYTES - 1, true],
            'at the cap'        => [Saml2Limits::DEFAULT_MAX_RESPONSE_BYTES, true],
            'one over the cap'  => [Saml2Limits::DEFAULT_MAX_RESPONSE_BYTES + 1, false],
        ];
    }

    /**
     * An encoded value longer than the cap is refused before it is decoded.
     *
     * @param  int  $length
     * @param  bool  $parsed
     * @return void
     */
    #[DataProvider('provideEncodedLengths')]
    public function testTheEncodedValueIsCappedBeforeItIsDecoded(int $length, bool $parsed): void
    {
        $result = $this->read(str_pad(self::response()->encoded(), $length, "\n"));

        self::assertSame($parsed, $result->isRead());
        self::assertSame($parsed ? null : 'too_large', $result->detail);
    }

    /**
     * Rows of `[padding, refused]`: a decoded document padded to around the
     * cap, and whether it is refused before it is parsed.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideDecodedLengths(): iterable
    {
        yield from [
            'one under the cap' => [-1, false],
            'at the cap'        => [0, false],
            'one over the cap'  => [1, true],
        ];
    }

    /**
     * A decoded document longer than its cap is refused before it is parsed.
     *
     * @param  int  $offset
     * @param  bool  $refused
     * @return void
     */
    #[DataProvider('provideDecodedLengths')]
    public function testTheDecodedDocumentIsCappedBeforeItIsParsed(int $offset, bool $refused): void
    {
        config()->set('sso.saml2.max_xml_bytes', Saml2Limits::MIN_MESSAGE_BYTES);

        $xml    = self::response()->toXml();
        $padded = $xml . str_repeat(' ', Saml2Limits::MIN_MESSAGE_BYTES + $offset - strlen($xml));

        self::assertSame($refused ? 'too_large' : null, $this->read(base64_encode($padded))->detail);
    }

    /**
     * A value that is not base64, or decodes to nothing, is refused; base64
     * wrapped over lines, as some providers post it, is read.
     *
     * @return void
     */
    public function testTheEncodedValueMustBeBase64(): void
    {
        self::assertSame(['response_invalid', 'not_base64'], $this->refusal('not base64*'));
        self::assertSame(['response_invalid', 'not_base64'], $this->refusal(''));
        self::assertTrue($this->read(chunk_split(self::response()->encoded(), 76, "\r\n"))->isRead());
    }

    /**
     * A document that is not XML, or declares a document type, is refused as
     * unparseable, and the caller's libxml error handling is as it was.
     *
     * @return void
     */
    public function testAnUnparseableDocumentIsRefusedAndLibxmlIsRestored(): void
    {
        $before = libxml_use_internal_errors(false);

        self::assertSame(['response_invalid', 'unparseable'], $this->refusal(base64_encode('<samlp:Response')));
        self::assertSame(['response_invalid', 'unparseable'], $this->refusal(base64_encode('<!DOCTYPE x [<!ENTITY a "b">]>' . self::response()->toXml())));
        self::assertSame(['response_invalid', 'schema'], $this->refusal(base64_encode('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>')));
        self::assertFalse(libxml_use_internal_errors($before));
        self::assertSame([], libxml_get_errors());
    }

    /**
     * An encrypted assertion is decrypted with the first key that unwraps its
     * session key, and read as a plain one, its own signature verified.
     *
     * @return void
     */
    public function testAnEncryptedAssertionIsDecryptedAndReadAsAPlainOne(): void
    {
        [$otherKey] = FakeSamlIdentityProvider::keyPair('other-sp');
        [, $spCert] = self::spKeys();
        $encrypted  = self::response()->encryptedFor($spCert);
        $result     = $this->read($encrypted->encoded(), ['keys' => [$otherKey, self::spKeys()[0]]]);

        $assertion = $result->response?->assertion();

        self::assertNotNull($assertion);
        self::assertSame([true, true, 'alice'], [$assertion->isEncrypted(), $assertion->isSigned(), $assertion->subject()?->nameId()?->value()]);
        self::assertTrue($this->read(self::response()->encryptedFor($spCert, 'rsa-oaep', 'aes192-gcm')->encoded())->isRead());
    }

    /**
     * Rows of `[response, policy]`: an encrypted response and the policy it is
     * read under, each failing to decrypt.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>}>
     */
    public static function provideDecryptionFailures(): iterable
    {
        yield from [
            'no decryption key'           => ['gcm', ['keys' => []]],
            'a key that does not unwrap'  => ['gcm', ['keys' => ['other']]],
            'rsa 1.5'                     => ['rsa15', []],
            'aes-256-gcm'                 => ['aes256', []],
            'a key transport not listed'  => ['gcm', ['transports' => ['http://www.w3.org/2009/xmlenc11#rsa-oaep']]],
            'a data algorithm not listed' => ['gcm', ['data' => ['http://www.w3.org/2009/xmlenc11#aes192-gcm']]],
            'aes-cbc not listed'          => ['cbc-signed', []],
            'aes-cbc unsigned response'   => ['cbc', ['data' => [...Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, self::AES128_CBC]]],
        ];
    }

    /**
     * Every decryption failure, of policy or of key, is the one failure.
     *
     * @param  string  $kind
     * @param  array<string, mixed>  $policy
     * @return void
     */
    #[DataProvider('provideDecryptionFailures')]
    public function testEveryDecryptionFailureIsOneIndistinguishableFailure(string $kind, array $policy): void
    {
        $certificate = self::spKeys()[1];
        $response    = match ($kind) {
            'rsa15'      => self::response()->signed(true, false)->encryptedFor($certificate, 'rsa-1_5', 'aes128-gcm'),
            'aes256'     => self::response()->encryptedFor($certificate, 'rsa-oaep-mgf1p', 'aes256-gcm'),
            'cbc-signed' => self::response()->signed(true, false)->encryptedFor($certificate, 'rsa-oaep-mgf1p', 'aes128-cbc'),
            'cbc'        => self::response()->encryptedFor($certificate, 'rsa-oaep-mgf1p', 'aes128-cbc'),
            default      => self::response()->encryptedFor($certificate),
        };

        if (($policy['keys'] ?? null) === ['other']) {
            $policy['keys'] = [FakeSamlIdentityProvider::keyPair('other')[0]];
        }

        self::assertSame(['decryption_failed', 'decryption'], $this->refusal($response->encoded(), $policy));
    }

    /**
     * AES-CBC decrypts once listed, inside a response whose own signature was
     * verified.
     *
     * @return void
     */
    public function testAesCbcDecryptsOnlyAfterAVerifiedResponseSignature(): void
    {
        $response = self::response()->signed(true, false)->encryptedFor(self::spKeys()[1], 'rsa-oaep-mgf1p', 'aes128-cbc');

        self::assertTrue($this->read($response->encoded(), ['data' => [...Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, self::AES128_CBC]])->isRead());
    }

    /**
     * The decryption keys are asked for only when there is something to
     * decrypt.
     *
     * @return void
     */
    public function testTheDecryptionKeysAreAskedForOnlyToDecrypt(): void
    {
        $this->read(self::response()->encoded());

        self::assertSame(0, $this->keysAsked);

        $this->read(self::response()->encryptedFor(self::spKeys()[1])->encoded());

        self::assertSame(1, $this->keysAsked);
    }

    /**
     * A decrypted assertion is held to the structure of a plain one: one
     * assertion at its root, its own signature its only one, an `ID` not the
     * response's, and valid against the assertion schema.
     *
     * @return void
     *
     * @throws \DOMException
     */
    public function testADecryptedAssertionIsHeldToThePlainStructure(): void
    {
        $options = self::responseOptions();
        $writer  = new ResponseWriter;
        $issuer  = '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.test/saml</saml:Issuer>';
        $sameId  = $writer->assertion([...$options, 'assertion_id' => $options['response_id']]);
        $invalid = str_replace('<saml:Issuer>', '<saml:Unknown/><saml:Issuer>', $writer->assertion($options));

        self::assertSame(['response_invalid', 'decrypted_structure'], $this->refusal(self::signedAround($issuer, $options)));
        self::assertSame(['response_invalid', 'duplicate_id'], $this->refusal(self::signedAround($sameId, $options)));
        self::assertSame(['response_invalid', 'schema'], $this->refusal(self::signedAround($invalid, $options)));
    }

    /**
     * The envelope reads every `InResponseTo` before anything is validated, and
     * nothing from a value it cannot read.
     *
     * @return void
     */
    public function testTheEnvelopeReadsEveryInResponseTo(): void
    {
        $adapter = app(SamlAdapter::class);

        $solicited   = $adapter->envelope(self::response()->inResponseTo(self::REQUEST_ID)->encoded());
        $unsolicited = $adapter->envelope(self::response()->inResponseTo(null)->encoded());
        $disagreeing = $adapter->envelope(self::response()->inResponseTo(self::REQUEST_ID)->with(['in_response_to' => '_other'])->encoded());
        $encrypted   = $adapter->envelope(self::response()->inResponseTo(null)->encryptedFor(self::spKeys()[1])->encoded());

        self::assertNotNull($solicited);
        self::assertNotNull($unsolicited);
        self::assertNotNull($disagreeing);
        self::assertNotNull($encrypted);
        self::assertSame([self::REQUEST_ID, self::REQUEST_ID], $solicited->inResponseTo());
        self::assertSame([self::REQUEST_ID, false, false], [$solicited->requestId(), $solicited->isUnsolicited(), $solicited->isEncrypted()]);
        self::assertSame([[], null, true], [$unsolicited->inResponseTo(), $unsolicited->requestId(), $unsolicited->isUnsolicited()]);
        self::assertSame([['_other', self::REQUEST_ID], null], [$disagreeing->inResponseTo(), $disagreeing->requestId()]);
        self::assertSame([true, true], [$encrypted->isEncrypted(), $encrypted->isUnsolicited()]);
        self::assertNull($adapter->envelope('not base64*'));
        self::assertNull($adapter->envelope(base64_encode('<!DOCTYPE x><x/>')));
    }

    /**
     * The envelope holds the encoded value to the response cap before it is
     * decoded, as a full read does: one under the cap and at it are read, one
     * over is not.
     *
     * @param  int  $length
     * @param  bool  $parsed
     * @return void
     */
    #[DataProvider('provideEncodedLengths')]
    public function testTheEnvelopesEncodedValueIsCappedBeforeItIsDecoded(int $length, bool $parsed): void
    {
        $encoded = str_pad(self::response()->inResponseTo(self::REQUEST_ID)->encoded(), $length, "\n");

        self::assertSame($length, strlen($encoded));
        self::assertSame($parsed ? self::REQUEST_ID : null, app(SamlAdapter::class)->envelope($encoded)?->requestId());
    }

    /**
     * The envelope holds the decoded document to the XML cap before it is
     * parsed, as a full read does: one under the cap and at it are read, one
     * over is not.
     *
     * @param  int  $offset
     * @param  bool  $refused
     * @return void
     */
    #[DataProvider('provideDecodedLengths')]
    public function testTheEnvelopesDecodedDocumentIsCappedBeforeItIsParsed(int $offset, bool $refused): void
    {
        config()->set('sso.saml2.max_xml_bytes', Saml2Limits::MIN_MESSAGE_BYTES);

        $xml    = self::response()->inResponseTo(self::REQUEST_ID)->toXml();
        $padded = $xml . str_repeat(' ', Saml2Limits::MIN_MESSAGE_BYTES + $offset - strlen($xml));

        self::assertSame($refused ? null : self::REQUEST_ID, app(SamlAdapter::class)->envelope(base64_encode($padded))?->requestId());
    }

    /**
     * The response every value test reads: signed only in its assertion, with
     * known ids, qualifiers and attributes, at a known instant.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse
     */
    private function readExample(): SamlResponse
    {
        $now        = CarbonImmutable::parse('2026-11-01T12:00:00Z');
        $deadline   = $now->addHours(8);
        $statements = [
            ['instant' => $now->subMinute(), 'session_index' => '_session-1', 'session_not_on_or_after' => $deadline, 'class' => FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT],
        ];
        $response = self::idp()->response(self::SP, self::ACS, $now)->inResponseTo(self::REQUEST_ID)->with([
            'response_id'       => '_response-1',
            'assertion_id'      => '_assertion-1',
            'name_qualifier'    => 'https://idp.example.test/saml',
            'sp_name_qualifier' => self::SP,
            'authn_statements'  => $statements,
            'attributes'        => ['email' => ['alice@example.test'], 'groups' => ['admins', 'staff']],
        ]);

        $read = $this->read($response->encoded())->response;

        self::assertNotNull($read);

        return $read;
    }

    /**
     * The response's assertion.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private static function assertionOf(SamlResponse $response): SamlAssertion
    {
        $assertion = $response->assertion();

        self::assertNotNull($assertion);

        return $assertion;
    }

    /**
     * The trusted identity provider.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }

    /**
     * An identity provider the policy does not trust.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function attacker(): FakeSamlIdentityProvider
    {
        return self::$attacker ??= new FakeSamlIdentityProvider('https://attacker.example.test/saml');
    }

    /**
     * The service provider's encryption key and certificate.
     *
     * @return array{0: string, 1: string}
     */
    private static function spKeys(): array
    {
        return self::$spKeys ??= FakeSamlIdentityProvider::keyPair('sp.example.test');
    }

    /**
     * A valid response to the request.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private static function response(): FakeSamlResponse
    {
        return self::idp()->response(self::SP, self::ACS)->inResponseTo(self::REQUEST_ID);
    }

    /**
     * A bearer confirmation answering the request, with no time limit.
     *
     * @return array<string, mixed>
     */
    private static function answeringConfirmation(): array
    {
        return [
            'method'          => FakeSamlResponse::BEARER,
            'data'            => true,
            'recipient'       => self::ACS,
            'not_before'      => null,
            'not_on_or_after' => null,
            'in_response_to'  => self::REQUEST_ID,
        ];
    }

    /**
     * A response holding the plaintext encrypted for the service provider,
     * signed by the trusted provider, encoded.
     *
     * @param  string  $plaintext
     * @param  ResponseOptions  $options
     * @return string
     *
     * @throws \DOMException
     */
    private static function signedAround(string $plaintext, array $options): string
    {
        $encrypted = (new AssertionEncryptor)->encrypt($plaintext, self::spKeys()[1]);
        $document  = new \DOMDocument;

        $document->loadXML((new ResponseWriter)->response($options, $encrypted));

        $root = $document->documentElement;

        self::assertNotNull($root);

        self::idp()->signer()->sign($root);

        return base64_encode((string) $document->saveXML($root));
    }

    /**
     * The options of a valid response to the request.
     *
     * @return ResponseOptions
     */
    private static function responseOptions(): array
    {
        return FakeSamlResponse::defaults(FakeSamlIdentityProvider::ENTITY_ID, self::SP, self::ACS, CarbonImmutable::now('UTC'));
    }

    /**
     * Read the encoded response under the default policy, with the trusted
     * certificates, algorithms, key transports, data algorithms and keys given
     * in place of the defaults.
     *
     * @param  string  $encoded
     * @param  array{certificates?: list<string>, algorithms?: list<string>, transports?: list<string>, data?: list<string>, keys?: list<string>}  $policy
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ReadResult
     */
    private function read(string $encoded, array $policy = []): ReadResult
    {
        $keys = $policy['keys'] ?? [self::spKeys()[0]];

        return app(SamlAdapter::class)->readResponse($encoded, new ResponsePolicy(
            $policy['certificates'] ?? [self::idp()->certificate()],
            $policy['algorithms']   ?? Saml2Settings::SIGNATURE_ALGORITHMS,
            $policy['transports']   ?? Saml2Settings::KEY_TRANSPORT_ALGORITHMS,
            $policy['data']         ?? Saml2Settings::DATA_ENCRYPTION_ALGORITHMS,
            function () use ($keys): array {
                $this->keysAsked++;

                return array_map(static fn (string $key): Secret => new Secret($key), $keys);
            },
        ));
    }

    /**
     * The reason and detail the encoded response is refused with.
     *
     * @param  string  $encoded
     * @param  array{certificates?: list<string>, algorithms?: list<string>, transports?: list<string>, data?: list<string>, keys?: list<string>}  $policy
     * @return array{0: ?string, 1: ?string}
     */
    private function refusal(string $encoded, array $policy = []): array
    {
        $result = $this->read($encoded, $policy);

        return [$result->reason?->value, $result->detail];
    }
}
