<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use Carbon\CarbonImmutable;
use SimpleSAML\SAML2\XML\saml\AbstractBaseID;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\Attribute;
use SimpleSAML\SAML2\XML\saml\AuthnStatement as LibraryAuthnStatement;
use SimpleSAML\SAML2\XML\saml\Conditions;
use SimpleSAML\SAML2\XML\saml\EncryptedID;
use SimpleSAML\SAML2\XML\saml\NameIDType;
use SimpleSAML\SAML2\XML\saml\Subject;
use SimpleSAML\SAML2\XML\saml\SubjectConfirmation as LibrarySubjectConfirmation;
use SimpleSAML\XMLSchema\Type\Interface\ValueTypeInterface;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlSubject;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;

/**
 * Reads a verified assertion into the package's own values (SSO-6.3): every
 * value comes from the object the library rebuilt from the bytes a trusted
 * signature covered, or from its decrypted form, through the library's getters,
 * or, for what the library does not model (statements and conditions of other
 * kinds, `Advice`), from that same verified element's children. Strings are
 * taken raw, as received, never trimmed or normalised (SSO-6.9), and instants
 * in UTC. Nothing here judges a value; it holds nothing between calls
 * (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AssertionMapper
{
    /** @var string The SAML assertion namespace. */
    private const string NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** @var list<string> The assertion's children that are not another kind of statement. */
    private const array ASSERTION_PARTS = ['Issuer', 'Subject', 'Conditions', 'Advice', 'AuthnStatement', 'AttributeStatement'];

    /** @var list<string> The conditions the package models. */
    private const array MODELLED_CONDITIONS = ['AudienceRestriction', 'OneTimeUse', 'ProxyRestriction'];

    /**
     * The verified assertion, as the package's value, with the verified element
     * it was read from.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\Assertion  $assertion
     * @param  \DOMElement  $element
     * @param  bool  $signed
     * @param  bool  $encrypted
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion
     */
    public function assertion(Assertion $assertion, \DOMElement $element, bool $signed, bool $encrypted): SamlAssertion
    {
        return new SamlAssertion(
            $assertion->getId()->getRawValue(),
            self::nameId($assertion->getIssuer()),
            self::instant($assertion->getIssueInstant()->toDateTime()),
            self::subject($assertion->getSubject()),
            self::conditions($assertion->getConditions(), $element),
            array_values(array_map(self::authnStatement(...), $assertion->getAuthnStatements())),
            self::attributes($assertion),
            [
                'encrypted_attributes' => self::encryptedAttributes($assertion),
                'other_statements'     => self::otherChildren($element, self::ASSERTION_PARTS),
                'advice'               => self::children($element, 'Advice') !== [],
                'signed'               => $signed,
                'encrypted'            => $encrypted,
            ],
        );
    }

    /**
     * A `NameIDType` value (a `NameID` or an `Issuer`), its text raw.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\NameIDType  $nameId
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId
     */
    public static function nameId(NameIDType $nameId): NameId
    {
        return new NameId(
            $nameId->getContent()->getRawValue(),
            $nameId->getFormat()?->getRawValue(),
            $nameId->getNameQualifier()?->getRawValue(),
            $nameId->getSPNameQualifier()?->getRawValue(),
            $nameId->getSPProvidedID()?->getRawValue(),
        );
    }

    /**
     * An instant, in UTC.
     *
     * @param  \DateTimeInterface  $instant
     * @return \Carbon\CarbonImmutable
     */
    public static function instant(\DateTimeInterface $instant): CarbonImmutable
    {
        return CarbonImmutable::instance($instant)->utc();
    }

    /**
     * The subject, with the kind of its identifier and its confirmations.
     *
     * @param  ?\SimpleSAML\SAML2\XML\saml\Subject  $subject
     * @return ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlSubject
     */
    private static function subject(?Subject $subject): ?SamlSubject
    {
        if ($subject === null) {
            return null;
        }

        $identifier = $subject->getIdentifier();

        $kind = match (true) {
            $identifier instanceof NameIDType     => IdentifierKind::NAME_ID,
            $identifier instanceof AbstractBaseID => IdentifierKind::BASE_ID,
            $identifier instanceof EncryptedID    => IdentifierKind::ENCRYPTED_ID,
            default                               => IdentifierKind::NONE,
        };

        $nameId        = $identifier instanceof NameIDType ? self::nameId($identifier) : null;
        $confirmations = [];

        foreach ($subject->getSubjectConfirmation() as $confirmation) {
            $confirmations[] = self::confirmation($confirmation);
        }

        return new SamlSubject($kind, $nameId, $confirmations);
    }

    /**
     * One subject confirmation, with its data when present.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\SubjectConfirmation  $confirmation
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation
     */
    private static function confirmation(LibrarySubjectConfirmation $confirmation): SubjectConfirmation
    {
        $method = $confirmation->getMethod()->getRawValue();
        $data   = $confirmation->getSubjectConfirmationData();

        if ($data === null) {
            return new SubjectConfirmation($method);
        }

        return new SubjectConfirmation(
            $method,
            true,
            self::optionalInstant($data->getNotBefore()?->toDateTime()),
            self::optionalInstant($data->getNotOnOrAfter()?->toDateTime()),
            $data->getRecipient()?->getRawValue(),
            $data->getInResponseTo()?->getRawValue(),
            $data->getAddress()?->getRawValue(),
        );
    }

    /**
     * The conditions, with the audiences of each restriction and the names of
     * every condition the package does not model.
     *
     * @param  ?\SimpleSAML\SAML2\XML\saml\Conditions  $conditions
     * @param  \DOMElement  $assertion
     * @return ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions
     */
    private static function conditions(?Conditions $conditions, \DOMElement $assertion): ?SamlConditions
    {
        if ($conditions === null) {
            return null;
        }

        // The library read its conditions from this same element
        $element    = self::children($assertion, 'Conditions')[0];
        $restricted = [];

        foreach ($conditions->getAudienceRestriction() as $restriction) {
            $restricted[] = array_values(array_map(static fn ($audience): string => $audience->getContent()->getRawValue(), $restriction->getAudience()));
        }

        return new SamlConditions(
            self::optionalInstant($conditions->getNotBefore()?->toDateTime()),
            self::optionalInstant($conditions->getNotOnOrAfter()?->toDateTime()),
            $restricted,
            count(self::children($element, 'OneTimeUse')),
            count(self::children($element, 'ProxyRestriction')),
            self::otherChildren($element, self::MODELLED_CONDITIONS),
        );
    }

    /**
     * One authentication statement.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\AuthnStatement  $statement
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement
     */
    private static function authnStatement(LibraryAuthnStatement $statement): AuthnStatement
    {
        return new AuthnStatement(
            self::instant($statement->getAuthnInstant()->toDateTime()),
            $statement->getSessionIndex()?->getRawValue(),
            self::optionalInstant($statement->getSessionNotOnOrAfter()?->toDateTime()),
            $statement->getAuthnContext()->getAuthnContextClassRef()?->getContent()->getRawValue(),
        );
    }

    /**
     * Every attribute of every attribute statement, in order.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\Assertion  $assertion
     * @return list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute>
     */
    private static function attributes(Assertion $assertion): array
    {
        $attributes = [];

        foreach ($assertion->getAttributeStatements() as $statement) {
            array_push($attributes, ...array_map(self::attribute(...), $statement->getAttributes()));
        }

        return $attributes;
    }

    /**
     * One attribute, each value's text raw, `null` for one that is not text.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\Attribute  $attribute
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute
     */
    private static function attribute(Attribute $attribute): SamlAttribute
    {
        $values = [];

        foreach ($attribute->getAttributeValues() as $value) {
            $content  = $value->getValue();
            $values[] = $content instanceof ValueTypeInterface ? $content->getRawValue() : null;
        }

        return new SamlAttribute(
            $attribute->getName()->getRawValue(),
            $attribute->getNameFormat()?->getRawValue(),
            $attribute->getFriendlyName()?->getRawValue(),
            $values,
        );
    }

    /**
     * How many encrypted attributes the assertion's statements carry.
     *
     * @param  \SimpleSAML\SAML2\XML\saml\Assertion  $assertion
     * @return int
     */
    private static function encryptedAttributes(Assertion $assertion): int
    {
        return array_sum(array_map(static fn ($statement): int => count($statement->getEncryptedAttributes()), $assertion->getAttributeStatements()));
    }

    /**
     * An instant in UTC, or `null`.
     *
     * @param  ?\DateTimeInterface  $instant
     * @return ?\Carbon\CarbonImmutable
     */
    private static function optionalInstant(?\DateTimeInterface $instant): ?CarbonImmutable
    {
        return $instant === null ? null : self::instant($instant);
    }

    /**
     * The element's children of the SAML assertion namespace with the local
     * name, in order.
     *
     * @param  \DOMElement  $element
     * @param  string  $name
     * @return list<\DOMElement>
     */
    private static function children(\DOMElement $element, string $name): array
    {
        $children = [];

        foreach ($element->childNodes as $child) {

            if (!$child instanceof \DOMElement || $child->namespaceURI !== self::NS_SAML || $child->localName !== $name) {
                continue;
            }

            $children[] = $child;
        }

        return $children;
    }

    /**
     * The qualified names (`{namespace}local`) of the element's children that
     * are not one of the SAML parts named, in order.
     *
     * @param  \DOMElement  $element
     * @param  list<string>  $parts
     * @return list<string>
     */
    private static function otherChildren(\DOMElement $element, array $parts): array
    {
        $others = [];

        foreach ($element->childNodes as $child) {

            if (!$child instanceof \DOMElement || self::isPart($child, $parts)) {
                continue;
            }

            $others[] = '{' . $child->namespaceURI . '}' . $child->localName;
        }

        return $others;
    }

    /**
     * Whether the element is one of the parts named, a SAML element of the
     * name. The assertion's own `ds:Signature` never reaches here: the element
     * is parsed from the bytes that signature digested, which its enveloped
     * transform removed it from, and the schema allows it no other.
     *
     * @param  \DOMElement  $element
     * @param  list<string>  $parts
     * @return bool
     */
    private static function isPart(\DOMElement $element, array $parts): bool
    {
        return $element->namespaceURI === self::NS_SAML && in_array($element->localName, $parts, true);
    }
}
