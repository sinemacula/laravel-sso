<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * What an unvalidated SAML response says of the request it answers. Untrusted:
 * it only names the request to consume; validation checks the signed value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Envelope implements \JsonSerializable
{
    use HoldsProviderValues;

    /**
     * Constructor.
     *
     * @param  list<string>  $inResponseTo
     * @param  bool  $encrypted
     */
    public function __construct(
        // Every `InResponseTo` attribute in the document, in document order
        #[\SensitiveParameter]
        array $inResponseTo,
        // Whether there is an `EncryptedAssertion`, its `InResponseTo` unread
        bool $encrypted,
    ) {
        $this->hold(['in_response_to' => $inResponseTo, 'encrypted' => $encrypted]);
    }

    /**
     * Every `InResponseTo` attribute in the document, in document order.
     *
     * @return list<string>
     */
    public function inResponseTo(): array
    {
        /** @var list<string> */
        return $this->held('in_response_to');
    }

    /**
     * Whether the response carries an `EncryptedAssertion`.
     *
     * @return bool
     */
    public function isEncrypted(): bool
    {
        return $this->held('encrypted') === true;
    }

    /**
     * Whether no `InResponseTo` appears anywhere in the document.
     *
     * @return bool
     */
    public function isUnsolicited(): bool
    {
        return $this->inResponseTo() === [];
    }

    /**
     * The one request id every `InResponseTo` names, or `null` when there is
     * none or they disagree.
     *
     * @return ?string
     */
    public function requestId(): ?string
    {
        $distinct = array_values(array_unique($this->inResponseTo()));

        return count($distinct) === 1 ? $distinct[0] : null;
    }
}
