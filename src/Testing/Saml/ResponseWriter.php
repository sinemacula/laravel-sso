<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Saml;

use Carbon\CarbonImmutable;

/**
 * Writes the XML of the fake SAML identity provider's responses and assertions
 * from a `FakeSamlResponse`'s options (SSO-12.4), every part in its SAML 2.0
 * schema position, every value escaped, and each part the options leave out
 * left out. A test tool; nothing here signs or encrypts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-import-type ResponseOptions from \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse
 */
final readonly class ResponseWriter
{
    /** @var string The SAML protocol namespace. */
    public const string NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /** @var string The SAML assertion namespace. */
    public const string NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** @var string The XML Schema instance namespace. */
    private const string NS_XSI = 'http://www.w3.org/2001/XMLSchema-instance';

    /**
     * The `samlp:Response` holding the assertion part given (an assertion, an
     * encrypted assertion, or nothing).
     *
     * @param  ResponseOptions  $options
     * @param  string  $assertion
     * @return string
     */
    public function response(array $options, string $assertion): string
    {
        return '<samlp:Response xmlns:samlp="' . self::NS_SAMLP . '" xmlns:saml="' . self::NS_SAML . '"'
            . self::attribute('ID', $options['response_id'])
            . ' Version="2.0"'
            . self::attribute('IssueInstant', self::instant($options['issue_instant']))
            . self::attribute('Destination', $options['destination'])
            . self::attribute('InResponseTo', $options['in_response_to']) . '>'
            . self::element('saml:Issuer', $options['issuer'])
            . self::status($options)
            . $assertion
            . '</samlp:Response>';
    }

    /**
     * The `saml:Assertion`, with its own namespace declarations so it stands
     * alone when signed or encrypted.
     *
     * @param  ResponseOptions  $options
     * @return string
     */
    public function assertion(array $options): string
    {
        return '<saml:Assertion xmlns:saml="' . self::NS_SAML . '" xmlns:xsi="' . self::NS_XSI . '"'
            . self::attribute('ID', $options['assertion_id'])
            . ' Version="2.0"'
            . self::attribute('IssueInstant', self::instant($options['assertion_issue_instant'])) . '>'
            . self::element('saml:Issuer', $options['assertion_issuer'])
            . self::subject($options)
            . self::conditions($options)
            . ($options['advice'] ? '<saml:Advice><saml:AssertionIDRef>_advised</saml:AssertionIDRef></saml:Advice>' : '')
            . implode('', array_map(self::authnStatement(...), $options['authn_statements']))
            . self::attributes($options)
            . '</saml:Assertion>';
    }

    /**
     * The `samlp:Status`.
     *
     * @param  ResponseOptions  $options
     * @return string
     */
    private static function status(array $options): string
    {
        $sub = $options['sub_status'] === null ? '' : '<samlp:StatusCode' . self::attribute('Value', $options['sub_status']) . '/>';

        return '<samlp:Status><samlp:StatusCode' . self::attribute('Value', $options['status']) . '>' . $sub . '</samlp:StatusCode>'
            . self::element('samlp:StatusMessage', $options['status_message'])
            . '</samlp:Status>';
    }

    /**
     * The `saml:Subject`, or nothing.
     *
     * @param  ResponseOptions  $options
     * @return string
     */
    private static function subject(array $options): string
    {
        if (!$options['subject']) {
            return '';
        }

        $nameId = $options['name_id'] === null ? '' : '<saml:NameID'
            . self::attribute('Format', $options['name_id_format'])
            . self::attribute('NameQualifier', $options['name_qualifier'])
            . self::attribute('SPNameQualifier', $options['sp_name_qualifier']) . '>'
            . htmlspecialchars($options['name_id'], ENT_XML1 | ENT_QUOTES) . '</saml:NameID>';

        return '<saml:Subject>' . $nameId . implode('', array_map(self::confirmation(...), $options['confirmations'])) . '</saml:Subject>';
    }

    /**
     * One `saml:SubjectConfirmation`.
     *
     * @param  array<string, mixed>  $confirmation
     * @return string
     */
    private static function confirmation(array $confirmation): string
    {
        $data = !$confirmation['data'] ? '' : '<saml:SubjectConfirmationData'
            . self::attribute('NotBefore', self::instant($confirmation['not_before']))
            . self::attribute('NotOnOrAfter', self::instant($confirmation['not_on_or_after']))
            . self::attribute('Recipient', $confirmation['recipient'])
            . self::attribute('InResponseTo', $confirmation['in_response_to']) . '/>';

        return '<saml:SubjectConfirmation' . self::attribute('Method', $confirmation['method']) . '>' . $data . '</saml:SubjectConfirmation>';
    }

    /**
     * The `saml:Conditions`, or nothing.
     *
     * @param  ResponseOptions  $options
     * @return string
     */
    private static function conditions(array $options): string
    {
        if (!$options['conditions']) {
            return '';
        }

        $restrictions = array_map(static fn (array $audiences): string => self::audienceRestriction($audiences), $options['audiences']);

        return '<saml:Conditions'
            . self::attribute('NotBefore', self::instant($options['not_before']))
            . self::attribute('NotOnOrAfter', self::instant($options['not_on_or_after'])) . '>'
            . implode('', $restrictions)
            . str_repeat('<saml:OneTimeUse/>', $options['one_time_use'])
            . str_repeat('<saml:ProxyRestriction Count="1"/>', $options['proxy_restriction'])
            . str_repeat('<saml:Condition xmlns:ex="urn:example:conditions" xsi:type="ex:Custom"/>', $options['unknown_conditions'])
            . '</saml:Conditions>';
    }

    /**
     * One `saml:AuthnStatement`.
     *
     * @param  array{instant: \Carbon\CarbonImmutable, session_index: ?string, session_not_on_or_after: ?\Carbon\CarbonImmutable, class: ?string}  $statement
     * @return string
     */
    private static function authnStatement(array $statement): string
    {
        $context = $statement['class'] === null
            ? '<saml:AuthnContextDeclRef>urn:example:declaration</saml:AuthnContextDeclRef>'
            : self::element('saml:AuthnContextClassRef', $statement['class']);

        return '<saml:AuthnStatement'
            . self::attribute('AuthnInstant', self::instant($statement['instant']))
            . self::attribute('SessionIndex', $statement['session_index'])
            . self::attribute('SessionNotOnOrAfter', self::instant($statement['session_not_on_or_after'])) . '>'
            . '<saml:AuthnContext>' . $context . '</saml:AuthnContext></saml:AuthnStatement>';
    }

    /**
     * The `saml:AttributeStatement`, or nothing when there is no attribute.
     *
     * @param  ResponseOptions  $options
     * @return string
     */
    private static function attributes(array $options): string
    {
        if ($options['attributes'] === []) {
            return '';
        }

        $attributes = '';

        foreach ($options['attributes'] as $name => $values) {
            $attributes .= '<saml:Attribute' . self::attribute('Name', $name) . self::attribute('NameFormat', $options['attribute_name_format']) . '>'
                . implode('', array_map(static fn (string $value): string => self::attributeValue($value), $values))
                . '</saml:Attribute>';
        }

        return '<saml:AttributeStatement>' . $attributes . '</saml:AttributeStatement>';
    }

    /**
     * One `saml:AudienceRestriction` naming the audiences.
     *
     * @param  list<string>  $audiences
     * @return string
     */
    private static function audienceRestriction(array $audiences): string
    {
        $elements = array_map(static fn (string $audience): string => self::element('saml:Audience', $audience), $audiences);

        return '<saml:AudienceRestriction>' . implode('', $elements) . '</saml:AudienceRestriction>';
    }

    /**
     * One `saml:AttributeValue` of the string type, holding the escaped text.
     *
     * @param  string  $value
     * @return string
     */
    private static function attributeValue(string $value): string
    {
        return '<saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema">'
            . htmlspecialchars($value, ENT_XML1 | ENT_QUOTES)
            . '</saml:AttributeValue>';
    }

    /**
     * An attribute with its value escaped, or nothing for `null`.
     *
     * @param  string  $name
     * @param  ?string  $value
     * @return string
     */
    private static function attribute(string $name, ?string $value): string
    {
        return $value === null ? '' : ' ' . $name . '="' . htmlspecialchars($value, ENT_XML1 | ENT_QUOTES) . '"';
    }

    /**
     * An element holding the escaped text, or nothing for `null`.
     *
     * @param  string  $name
     * @param  ?string  $text
     * @return string
     */
    private static function element(string $name, ?string $text): string
    {
        return $text === null ? '' : '<' . $name . '>' . htmlspecialchars($text, ENT_XML1 | ENT_QUOTES) . '</' . $name . '>';
    }

    /**
     * An instant as SAML writes one, in UTC with a `Z`, or `null`.
     *
     * @param  ?\Carbon\CarbonImmutable  $instant
     * @return ?string
     */
    private static function instant(?CarbonImmutable $instant): ?string
    {
        return $instant?->utc()->format('Y-m-d\TH:i:s\Z');
    }
}
