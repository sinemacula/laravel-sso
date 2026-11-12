<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * A response's one assertion, read only from verified content. The adapter
 * answers only an assertion that its own or the response's signature covers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SamlAssertion implements \JsonSerializable
{
    use HoldsProviderValues;

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $issuer
     * @param  \Carbon\CarbonImmutable  $issueInstant
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlSubject  $subject
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions  $conditions
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement>  $authnStatements
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute>  $attributes
     * @param  array{encrypted_attributes?: int, other_statements?: list<string>, advice?: bool, signed?: bool, encrypted?: bool}  $facts
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(
        // The assertion's identifier
        string $id,
        // The issuer that made the assertion
        NameId $issuer,
        // The instant the assertion was issued
        CarbonImmutable $issueInstant,
        // The subject the assertion is about
        ?SamlSubject $subject = null,
        // The conditions the assertion is valid under
        ?SamlConditions $conditions = null,
        // Every authentication statement, in order
        array $authnStatements = [],
        // Every attribute of every attribute statement, in order
        array $attributes = [],
        // Counts of unread parts, and whether it was signed or encrypted
        array $facts = [],
    ) {
        $this->hold([
            'id'                   => $id,
            'issuer'               => $issuer,
            'issue_instant'        => $issueInstant,
            'subject'              => $subject,
            'conditions'           => $conditions,
            'authn_statements'     => $authnStatements,
            'attributes'           => $attributes,
            'encrypted_attributes' => $facts['encrypted_attributes'] ?? 0,
            'other_statements'     => $facts['other_statements']     ?? [],
            'advice'               => $facts['advice']               ?? false,
            'signed'               => $facts['signed']               ?? false,
            'encrypted'            => $facts['encrypted']            ?? false,
        ]);
    }

    /**
     * The `ID` attribute.
     *
     * @return string
     */
    public function id(): string
    {
        /** @var string */
        return $this->held('id');
    }

    /**
     * The `Issuer`.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId
     */
    public function issuer(): NameId
    {
        /** @var \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId */
        return $this->held('issuer');
    }

    /**
     * The `IssueInstant` attribute.
     *
     * @return \Carbon\CarbonImmutable
     */
    public function issueInstant(): CarbonImmutable
    {
        /** @var \Carbon\CarbonImmutable */
        return $this->held('issue_instant');
    }

    /**
     * The `Subject`, or `null` when absent.
     *
     * @return ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlSubject
     */
    public function subject(): ?SamlSubject
    {
        /** @var ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlSubject */
        return $this->held('subject');
    }

    /**
     * The `Conditions`, or `null` when absent.
     *
     * @return ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions
     */
    public function conditions(): ?SamlConditions
    {
        /** @var ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions */
        return $this->held('conditions');
    }

    /**
     * Every `AuthnStatement`, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement>
     */
    public function authnStatements(): array
    {
        /** @var list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement> */
        return $this->held('authn_statements');
    }

    /**
     * Every attribute of every `AttributeStatement`, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute>
     */
    public function attributes(): array
    {
        /** @var list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute> */
        return $this->held('attributes');
    }

    /**
     * How many `EncryptedAttribute`s it carries; none is ever decrypted.
     *
     * @return int
     */
    public function encryptedAttributes(): int
    {
        /** @var int */
        return $this->held('encrypted_attributes');
    }

    /**
     * The qualified name of every other kind of statement, in order.
     *
     * @return list<string>
     */
    public function otherStatements(): array
    {
        /** @var list<string> */
        return $this->held('other_statements');
    }

    /**
     * Whether it carries `Advice`.
     *
     * @return bool
     */
    public function hasAdvice(): bool
    {
        return $this->held('advice') === true;
    }

    /**
     * Whether it carries its own signature, which the adapter verified.
     *
     * @return bool
     */
    public function isSigned(): bool
    {
        return $this->held('signed') === true;
    }

    /**
     * Whether it arrived as an `EncryptedAssertion`.
     *
     * @return bool
     */
    public function isEncrypted(): bool
    {
        return $this->held('encrypted') === true;
    }
}
