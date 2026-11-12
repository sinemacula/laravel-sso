<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Saml;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use SineMacula\Laravel\Sso\Testing\Saml\ResponseWriter;

/**
 * Unit tests for the XML the fake SAML identity provider writes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-import-type ResponseOptions from \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
 */
#[CoversClass(ResponseWriter::class)]
final class ResponseWriterTest extends TestCase
{
    /** @var string The namespace declarations of a response. */
    private const string RESPONSE_NAMESPACES = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';

    /** @var string The namespace declarations of an assertion. */
    private const string ASSERTION_NAMESPACES = 'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';

    /** @var string The opening of a string attribute value. */
    private const string VALUE = '<saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema">';

    /** @var string The text that needs every XML escape. */
    private const string HOSTILE = 'Tom & "Jerry" <it\'s>';

    /** @var string That text escaped. */
    private const string ESCAPED = 'Tom &amp; &quot;Jerry&quot; &lt;it&apos;s&gt;';

    /**
     * The namespace constants name the SAML protocol and assertion namespaces.
     *
     * @return void
     */
    public function testNamesTheSamlNamespaces(): void
    {
        self::assertSame('urn:oasis:names:tc:SAML:2.0:protocol', ResponseWriter::NS_SAMLP);
        self::assertSame('urn:oasis:names:tc:SAML:2.0:assertion', ResponseWriter::NS_SAML);
    }

    /**
     * A response with every part is written in schema order, every value
     * escaped and the instant in UTC.
     *
     * @return void
     */
    public function testWritesAFullResponse(): void
    {
        $changes = [
            'issue_instant'  => CarbonImmutable::parse('2026-11-01T14:00:00+02:00'),
            'destination'    => 'https://sp.example.test/acs?a=1&b=2',
            'in_response_to' => '_request',
            'issuer'         => self::HOSTILE,
            'status'         => 'urn:oasis:names:tc:SAML:2.0:status:Responder',
            'sub_status'     => 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
            'status_message' => self::HOSTILE,
        ];

        self::assertSame(
            '<samlp:Response ' . self::RESPONSE_NAMESPACES
                . ' ID="_response" Version="2.0" IssueInstant="2026-11-01T12:00:00Z" Destination="https://sp.example.test/acs?a=1&amp;b=2" InResponseTo="_request">'
                . '<saml:Issuer>' . self::ESCAPED . '</saml:Issuer>'
                . '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">'
                . '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/></samlp:StatusCode>'
                . '<samlp:StatusMessage>' . self::ESCAPED . '</samlp:StatusMessage></samlp:Status>'
                . '<assertion/>'
                . '</samlp:Response>',
            self::writtenResponse($changes, '<assertion/>'),
        );
    }

    /**
     * A response without an issuer, destination, `InResponseTo`, sub-status,
     * status message or assertion leaves each of them out.
     *
     * @return void
     */
    public function testLeavesOutWhatAResponseDoesNotHave(): void
    {
        $changes = ['issuer' => null, 'destination' => null, 'in_response_to' => null, 'sub_status' => null, 'status_message' => null];

        self::assertSame(
            '<samlp:Response ' . self::RESPONSE_NAMESPACES . ' ID="_response" Version="2.0" IssueInstant="2026-11-01T12:00:00Z">'
                . '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>'
                . '</samlp:Response>',
            self::writtenResponse($changes, ''),
        );
    }

    /**
     * An assertion with every part is written in schema order, repeats as
     * given, values escaped and instants in UTC.
     *
     * @return void
     */
    public function testWritesAFullAssertion(): void
    {
        self::assertSame(
            '<saml:Assertion ' . self::ASSERTION_NAMESPACES . ' ID="_assertion" Version="2.0" IssueInstant="2026-11-01T12:00:01Z">'
                . '<saml:Issuer>https://idp.example.test/assertion</saml:Issuer>'
                . self::fullSubject()
                . self::fullConditions()
                . '<saml:Advice><saml:AssertionIDRef>_advised</saml:AssertionIDRef></saml:Advice>'
                . '<saml:AuthnStatement AuthnInstant="2026-11-01T11:59:00Z" SessionIndex="_session" SessionNotOnOrAfter="2026-11-01T20:00:00Z">'
                . '<saml:AuthnContext><saml:AuthnContextClassRef>' . FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT . '</saml:AuthnContextClassRef></saml:AuthnContext>'
                . '</saml:AuthnStatement>'
                . '<saml:AuthnStatement AuthnInstant="2026-11-01T11:58:00Z">'
                . '<saml:AuthnContext><saml:AuthnContextDeclRef>urn:example:declaration</saml:AuthnContextDeclRef></saml:AuthnContext>'
                . '</saml:AuthnStatement>'
                . '<saml:AttributeStatement>'
                . '<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
                . self::VALUE . 'alice@example.test</saml:AttributeValue></saml:Attribute>'
                . '<saml:Attribute Name="a&amp;b" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
                . self::VALUE . self::ESCAPED . '</saml:AttributeValue>' . self::VALUE . 'second</saml:AttributeValue></saml:Attribute>'
                . '</saml:AttributeStatement>'
                . '</saml:Assertion>',
            self::writtenAssertion(self::fullAssertion()),
        );
    }

    /**
     * An assertion without a subject, conditions, advice, statements or
     * attributes holds its issuer alone.
     *
     * @return void
     */
    public function testLeavesOutWhatAnAssertionDoesNotHave(): void
    {
        $changes = ['subject' => false, 'conditions' => false, 'advice' => false, 'authn_statements' => [], 'attributes' => []];

        self::assertSame(
            '<saml:Assertion ' . self::ASSERTION_NAMESPACES . ' ID="_assertion" Version="2.0" IssueInstant="2026-11-01T12:00:01Z">'
                . '<saml:Issuer>https://idp.example.test/assertion</saml:Issuer>'
                . '</saml:Assertion>',
            self::writtenAssertion($changes),
        );
    }

    /**
     * A subject, conditions and attribute with nothing optional are written
     * bare.
     *
     * @return void
     */
    public function testWritesBareParts(): void
    {
        $nameId = [
            'name_id_format'    => null,
            'name_qualifier'    => null,
            'sp_name_qualifier' => null,
            'confirmations'     => [],
            'conditions'        => false,
            'authn_statements'  => [],
            'attributes'        => [],
        ];
        $empty = [
            'name_id'               => null,
            'confirmations'         => [],
            'not_before'            => null,
            'not_on_or_after'       => null,
            'audiences'             => [],
            'one_time_use'          => 0,
            'proxy_restriction'     => 0,
            'unknown_conditions'    => 0,
            'authn_statements'      => [],
            'attributes'            => ['email' => []],
            'attribute_name_format' => null,
        ];
        $opening = '<saml:Assertion ' . self::ASSERTION_NAMESPACES . ' ID="_assertion" Version="2.0" IssueInstant="2026-11-01T12:00:01Z">'
            . '<saml:Issuer>https://idp.example.test/assertion</saml:Issuer>';

        self::assertSame(
            $opening . '<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>',
            self::writtenAssertion($nameId),
        );
        self::assertSame(
            $opening . '<saml:Subject></saml:Subject><saml:Conditions></saml:Conditions>'
                . '<saml:AttributeStatement><saml:Attribute Name="email"></saml:Attribute></saml:AttributeStatement></saml:Assertion>',
            self::writtenAssertion($empty),
        );
    }

    /**
     * The full assertion's subject: a qualified, escaped `NameID`, then
     * confirmations with all, no and empty data.
     *
     * @return string
     */
    private static function fullSubject(): string
    {
        return '<saml:Subject>'
            . '<saml:NameID Format="' . FakeSamlResponse::PERSISTENT . '" NameQualifier="idp-qualifier" SPNameQualifier="sp-qualifier">' . self::ESCAPED . '</saml:NameID>'
            . '<saml:SubjectConfirmation Method="' . FakeSamlResponse::BEARER . '">'
            . '<saml:SubjectConfirmationData NotBefore="2026-11-01T11:59:00Z" NotOnOrAfter="2026-11-01T12:05:00Z"'
            . ' Recipient="https://sp.example.test/acs?a=1&amp;b=2" InResponseTo="_request"/>'
            . '</saml:SubjectConfirmation>'
            . '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"></saml:SubjectConfirmation>'
            . '<saml:SubjectConfirmation Method="' . FakeSamlResponse::BEARER . '"><saml:SubjectConfirmationData/></saml:SubjectConfirmation>'
            . '</saml:Subject>';
    }

    /**
     * The conditions of the full assertion: the bounds, two audience
     * restrictions in order, then the counted conditions in schema order.
     *
     * @return string
     */
    private static function fullConditions(): string
    {
        return '<saml:Conditions NotBefore="2026-11-01T11:59:00Z" NotOnOrAfter="2026-11-01T12:05:00Z">'
            . '<saml:AudienceRestriction><saml:Audience>https://sp.example.test</saml:Audience><saml:Audience>a&amp;b</saml:Audience></saml:AudienceRestriction>'
            . '<saml:AudienceRestriction><saml:Audience>https://third.example.test</saml:Audience></saml:AudienceRestriction>'
            . '<saml:OneTimeUse/><saml:OneTimeUse/>'
            . '<saml:ProxyRestriction Count="1"/>'
            . '<saml:Condition xmlns:ex="urn:example:conditions" xsi:type="ex:Custom"/><saml:Condition xmlns:ex="urn:example:conditions" xsi:type="ex:Custom"/>'
            . '<saml:Condition xmlns:ex="urn:example:conditions" xsi:type="ex:Custom"/>'
            . '</saml:Conditions>';
    }

    /**
     * The changes that make the full assertion, its instants given outside UTC.
     *
     * @return array<string, mixed>
     */
    private static function fullAssertion(): array
    {
        $local = static fn (string $time): CarbonImmutable => CarbonImmutable::parse('2026-11-01T' . $time . '+02:00');

        return [
            'assertion_issue_instant' => $local('14:00:01'),
            'name_id'                 => self::HOSTILE,
            'name_qualifier'          => 'idp-qualifier',
            'sp_name_qualifier'       => 'sp-qualifier',
            'confirmations'           => [
                [
                    'method'     => FakeSamlResponse::BEARER, 'data' => true, 'recipient' => 'https://sp.example.test/acs?a=1&b=2',
                    'not_before' => $local('13:59:00'), 'not_on_or_after' => $local('14:05:00'), 'in_response_to' => '_request',
                ],
                [
                    'method'     => 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key', 'data' => false, 'recipient' => 'https://ignored.example.test',
                    'not_before' => $local('13:59:00'), 'not_on_or_after' => $local('14:05:00'), 'in_response_to' => '_ignored',
                ],
                ['method' => FakeSamlResponse::BEARER, 'data' => true, 'recipient' => null, 'not_before' => null, 'not_on_or_after' => null, 'in_response_to' => null],
            ],
            'not_before'         => $local('13:59:00'),
            'not_on_or_after'    => $local('14:05:00'),
            'audiences'          => [['https://sp.example.test', 'a&b'], ['https://third.example.test']],
            'one_time_use'       => 2,
            'proxy_restriction'  => 1,
            'unknown_conditions' => 3,
            'advice'             => true,
            'authn_statements'   => [
                [
                    'instant'                 => $local('13:59:00'),
                    'session_index'           => '_session',
                    'session_not_on_or_after' => $local('22:00:00'),
                    'class'                   => FakeSamlResponse::PASSWORD_PROTECTED_TRANSPORT,
                ],
                ['instant' => $local('13:58:00'), 'session_index' => null, 'session_not_on_or_after' => null, 'class' => null],
            ],
            'attributes' => ['email' => ['alice@example.test'], 'a&b' => [self::HOSTILE, 'second']],
        ];
    }

    /**
     * The response the writer writes from the fixed options with the changes
     * given, holding the assertion part.
     *
     * @param  array<string, mixed>  $changes
     * @param  string  $assertion
     * @return string
     */
    private static function writtenResponse(array $changes, string $assertion): string
    {
        /** @var ResponseOptions $options */
        $options = [...self::fixed(), ...$changes];

        return (new ResponseWriter)->response($options, $assertion);
    }

    /**
     * The assertion the writer writes from the fixed options with the changes
     * given.
     *
     * @param  array<string, mixed>  $changes
     * @return string
     */
    private static function writtenAssertion(array $changes): string
    {
        /** @var ResponseOptions $options */
        $options = [...self::fixed(), ...$changes];

        return (new ResponseWriter)->assertion($options);
    }

    /**
     * The fake provider's default options at noon, with fixed identifiers, an
     * assertion issued a second later and an issuer of its own.
     *
     * @return array<string, mixed>
     */
    private static function fixed(): array
    {
        $noon = CarbonImmutable::parse('2026-11-01T12:00:00Z');

        return [
            ...FakeSamlResponse::defaults('https://idp.example.test/saml', 'https://sp.example.test', 'https://sp.example.test/acs', $noon),
            'response_id'             => '_response',
            'assertion_id'            => '_assertion',
            'assertion_issue_instant' => $noon->addSecond(),
            'assertion_issuer'        => 'https://idp.example.test/assertion',
        ];
    }
}
