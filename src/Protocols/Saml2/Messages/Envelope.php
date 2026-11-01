<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * What a SAML response says of the request it answers, read before anything in
 * it is validated (SSO-5.3, SSO-5.8, SSO-6.6): every `InResponseTo` attribute
 * anywhere in the parsed document, in document order, and whether it carries an
 * encrypted assertion, whose own `InResponseTo` cannot be seen until it is
 * decrypted.
 *
 * It is never trusted: correlation only names the request the pipeline
 * consumes; the response validation then requires the signed `InResponseTo` to
 * equal the consumed request's id. An `InResponseTo` anywhere keeps the
 * response from being handled as unsolicited, and values that disagree leave it
 * uncorrelated.
 *
 * Every value is attacker-supplied and unauthenticated, so it is held as any
 * provider value is (`Concerns\HoldsProviderValues`): behind its accessors,
 * never shown by a dump, an array cast or `json_encode()`, and never
 * serialised.
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
        // Whether the response carries an `EncryptedAssertion`
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
     * The one request id every `InResponseTo` names, compared exactly, or
     * `null` when there is none or they disagree.
     *
     * @return ?string
     */
    public function requestId(): ?string
    {
        $distinct = array_values(array_unique($this->inResponseTo()));

        return count($distinct) === 1 ? $distinct[0] : null;
    }
}
