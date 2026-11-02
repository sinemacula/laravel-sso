<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind;

/**
 * A verified assertion's `Subject` (SAML 2.0 Core §2.4), as the SAML adapter
 * read it: which kind of identifier it carries (a `NameID`, a `BaseID`, an
 * `EncryptedID`, or none), the `NameID` when it is one, and every
 * `SubjectConfirmation` in order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SamlSubject implements \JsonSerializable
{
    use HoldsProviderValues;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind  $kind
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId  $nameId
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation>  $confirmations
     */
    public function __construct(
        // Which kind of identifier the subject carries
        IdentifierKind $kind,
        // The `NameID`, when the identifier is one
        ?NameId $nameId = null,
        // Every `SubjectConfirmation`, in order
        array $confirmations = [],
    ) {
        $this->hold(['kind' => $kind, 'name_id' => $nameId, 'confirmations' => $confirmations]);
    }

    /**
     * Which kind of identifier the subject carries.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind
     */
    public function kind(): IdentifierKind
    {
        /** @var \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\IdentifierKind */
        return $this->held('kind');
    }

    /**
     * The `NameID`, or `null` when the identifier is not one.
     *
     * @return ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId
     */
    public function nameId(): ?NameId
    {
        /** @var ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\NameId */
        return $this->held('name_id');
    }

    /**
     * Every `SubjectConfirmation`, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation>
     */
    public function confirmations(): array
    {
        /** @var list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation> */
        return $this->held('confirmations');
    }
}
