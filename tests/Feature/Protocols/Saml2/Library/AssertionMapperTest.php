<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\AssertionMapper;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlAdapter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use SineMacula\Laravel\Sso\Testing\Saml\ResponseWriter;
use Tests\TestCase;

/**
 * Feature tests for how a verified assertion is read into the package's values
 * (SSO-6.3), through the adapter: every optional value left out reads as
 * `null`, each kind of subject identifier, every confirmation in order, the
 * conditions the package counts, and the statements, conditions, advice and
 * encrypted attributes the library does not model, read from the verified
 * element.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-import-type ResponseOptions from \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
 */
#[CoversClass(AssertionMapper::class)]
final class AssertionMapperTest extends TestCase
{
    /** @var string The service provider's entity id. */
    private const string SP = 'https://sp.example.test/saml';

    /** @var string The assertion consumer service URL. */
    private const string ACS = 'https://sp.example.test/saml/acs';

    /** @var string The sender-vouches confirmation method. */
    private const string SENDER_VOUCHES = 'urn:oasis:names:tc:SAML:2.0:cm:sender-vouches';

    /** @var string The XML encryption namespace. */
    private const string XENC = 'http://www.w3.org/2001/04/xmlenc#';

    /** @var string The SAML assertion namespace, as an outlined name shows it. */
    private const string SAML = '{urn:oasis:names:tc:SAML:2.0:assertion}';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The identity provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /**
     * Optional values the response leaves out read as `null`, the counted
     * conditions and the advice are read, and the confirmations keep their
     * order, one without data read as such.
     *
     * @return void
     */
    public function testReadsWhatAnAssertionLeavesOutAndWhatItCounts(): void
    {
        $assertion  = $this->read(self::sparseResponse()->encoded());
        $conditions = $assertion->conditions()         ?? self::fail('The assertion has no conditions.');
        $statement  = $assertion->authnStatements()[0] ?? self::fail('The assertion has no statement.');
        $attribute  = $assertion->attributes()[0]      ?? self::fail('The assertion has no attribute.');
        $subject    = $assertion->subject()            ?? self::fail('The assertion has no subject.');

        self::assertSame([null, null, [[self::SP, 'https://other.example.test'], [self::SP]], 1, 1, []], [
            $conditions->notBefore(), $conditions->notOnOrAfter(), $conditions->audienceRestrictions(),
            $conditions->oneTimeUse(), $conditions->proxyRestrictions(), $conditions->otherConditions(),
        ]);
        self::assertSame(['2026-11-01T11:59:00+00:00', null, null, null], [
            $statement->authnInstant()->toIso8601String(), $statement->sessionIndex(), $statement->sessionNotOnOrAfter(), $statement->contextClassRef(),
        ]);
        self::assertSame(
            ['email', null, null, ['alice@example.test', 'alice@example.org']],
            [$attribute->name(), $attribute->nameFormat(), $attribute->friendlyName(), $attribute->values()],
        );
        self::assertSame([true, [], 0], [$assertion->hasAdvice(), $assertion->otherStatements(), $assertion->encryptedAttributes()]);
        self::assertSame([
            [FakeSamlResponse::BEARER, true, '2026-11-01T11:59:00+00:00', null, null, null],
            [self::SENDER_VOUCHES, false, null, null, null, null],
        ], array_map(self::confirmation(...), $subject->confirmations()));
    }

    /**
     * A subject with no identifier reads as such, with no NameID; one with an
     * encrypted identifier reads as encrypted, with no NameID either.
     *
     * @return void
     *
     * @throws \DOMException
     */
    public function testReadsTheKindOfIdentifier(): void
    {
        $none      = $this->read(self::idp()->response(self::SP, self::ACS)->with(['name_id' => null])->encoded())->subject();
        $encrypted = $this->read(self::edited([], static fn (string $xml): string => (string) preg_replace(
            '#<saml:NameID[^>]*>[^<]*</saml:NameID>#',
            '<saml:EncryptedID>' . self::encryptedData() . '</saml:EncryptedID>',
            $xml,
        )))->subject();

        self::assertSame([IdentifierKind::NONE, null], [$none?->kind(), $none?->nameId()]);
        self::assertSame([IdentifierKind::ENCRYPTED_ID, null], [$encrypted?->kind(), $encrypted?->nameId()]);
        self::assertSame(IdentifierKind::NAME_ID, $this->read(self::idp()->response(self::SP, self::ACS)->encoded())->subject()?->kind());
    }

    /**
     * Statements and conditions of kinds the package does not model are named
     * in order, every one of them, and the encrypted attributes of every
     * attribute statement are counted; the parts it models are not named.
     *
     * @return void
     *
     * @throws \DOMException
     */
    public function testNamesWhatTheLibraryDoesNotModel(): void
    {
        $decision = '<saml:AuthzDecisionStatement Resource="urn:example:resource" Decision="Permit">'
            . '<saml:Action Namespace="urn:example:actions">read</saml:Action></saml:AuthzDecisionStatement>';
        $encrypted = '<saml:EncryptedAttribute>' . self::encryptedData() . '</saml:EncryptedAttribute>';
        $assertion = $this->read(self::edited(['one_time_use' => 1], static fn (string $xml): string => str_replace(
            ['<saml:OneTimeUse/>', '</saml:Attribute></saml:AttributeStatement>', '</saml:Assertion>'],
            [
                '<saml:OneTimeUse/><saml:Condition xsi:type="saml:OneTimeUseType"/><saml:Condition xsi:type="saml:ProxyRestrictionType"/>',
                '</saml:Attribute>' . $encrypted . '</saml:AttributeStatement><saml:AttributeStatement>' . $encrypted . '</saml:AttributeStatement>',
                $decision . $decision . '</saml:Assertion>',
            ],
            $xml,
        )));

        $conditions = $assertion->conditions() ?? self::fail('The assertion has no conditions.');

        self::assertSame([self::SAML . 'AuthzDecisionStatement', self::SAML . 'AuthzDecisionStatement'], $assertion->otherStatements());
        self::assertSame([self::SAML . 'Condition', self::SAML . 'Condition'], $conditions->otherConditions());
        self::assertSame([1, 0, 2, false], [$conditions->oneTimeUse(), $conditions->proxyRestrictions(), $assertion->encryptedAttributes(), $assertion->hasAdvice()]);
    }

    /**
     * A response that leaves out every optional value it can, counts one
     * `OneTimeUse` and one `ProxyRestriction`, and carries advice: a bearer
     * confirmation with data but only a `NotBefore`, then a sender-vouches one
     * with no data.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
     */
    private static function sparseResponse(): FakeSamlResponse
    {
        $now     = CarbonImmutable::parse('2026-11-01T12:00:00Z');
        $nothing = ['recipient' => null, 'not_before' => null, 'not_on_or_after' => null, 'in_response_to' => null];

        return self::idp()->response(self::SP, self::ACS, $now)->with([
            'confirmations' => [
                ['method' => FakeSamlResponse::BEARER, 'data' => true, ...$nothing, 'not_before' => $now->subMinute()],
                ['method' => self::SENDER_VOUCHES, 'data' => false, ...$nothing],
            ],
            'not_before'            => null,
            'not_on_or_after'       => null,
            'audiences'             => [[self::SP, 'https://other.example.test'], [self::SP]],
            'one_time_use'          => 1,
            'proxy_restriction'     => 1,
            'advice'                => true,
            'authn_statements'      => [['instant' => $now->subMinute(), 'session_index' => null, 'session_not_on_or_after' => null, 'class' => null]],
            'attributes'            => ['email' => ['alice@example.test', 'alice@example.org']],
            'attribute_name_format' => null,
        ]);
    }

    /**
     * A confirmation's method, whether it has data, its `NotBefore`, and its
     * `NotOnOrAfter`, `Recipient` and `InResponseTo`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation  $confirmation
     * @return list<mixed>
     */
    private static function confirmation(SubjectConfirmation $confirmation): array
    {
        return [
            $confirmation->method(), $confirmation->hasData(), $confirmation->notBefore()?->toIso8601String(),
            $confirmation->notOnOrAfter(), $confirmation->recipient(), $confirmation->inResponseTo(),
        ];
    }

    /**
     * A response whose assertion's XML is edited before the provider signs it,
     * encoded.
     *
     * @param  array<string, mixed>  $changes
     * @param  callable(string): string  $edit
     * @return string
     *
     * @throws \DOMException
     */
    private static function edited(array $changes, callable $edit): string
    {
        /** @var ResponseOptions $options */
        $options  = [...FakeSamlResponse::defaults(FakeSamlIdentityProvider::ENTITY_ID, self::SP, self::ACS, CarbonImmutable::now('UTC')), ...$changes];
        $writer   = new ResponseWriter;
        $document = new \DOMDocument;

        self::assertTrue($document->loadXML($edit($writer->assertion($options))));

        $root = $document->documentElement ?? self::fail('The assertion has no root.');

        self::idp()->signer()->sign($root);

        return base64_encode($writer->response($options, (string) $document->saveXML($root)));
    }

    /**
     * An `xenc:EncryptedData` of an element, never decrypted.
     *
     * @return string
     */
    private static function encryptedData(): string
    {
        return '<xenc:EncryptedData xmlns:xenc="' . self::XENC . '" Type="' . self::XENC . 'Element">'
            . '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>'
            . '<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>';
    }

    /**
     * The assertion of the encoded response, read under the default policy with
     * the provider trusted.
     *
     * @param  string  $encoded
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    private function read(string $encoded): SamlAssertion
    {
        $result = app(SamlAdapter::class)->readResponse($encoded, new ResponsePolicy(
            [self::idp()->certificate()],
            Saml2Settings::SIGNATURE_ALGORITHMS,
            Saml2Settings::KEY_TRANSPORT_ALGORITHMS,
            Saml2Settings::DATA_ENCRYPTION_ALGORITHMS,
            static fn (): array => [],
        ));

        self::assertSame([null, null], [$result->reason?->value, $result->detail]);

        return $result->response?->assertion() ?? self::fail('The response has no assertion.');
    }

    /**
     * The identity provider.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }
}
