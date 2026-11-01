<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\Enums\MessageKind;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Envelope;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ReadResult;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Limits;

/**
 * The package's SAML adapter for responses (SSO-6.1 to SSO-6.3, SSO-6.7,
 * SSO-6.8, SSO-6.11, `docs/design/saml-adapter.md`): the one entry the SAML
 * driver reads a posted `SAMLResponse` through. Every call into
 * `simplesamlphp/saml2` and `simplesamlphp/xml-security` is made inside this
 * namespace (`Protocols\Saml2\Library`), and nothing outside it names either
 * library; an architecture test holds that, forbids `verify()` without a
 * verifier, and forbids the library's `Response\Processor` and
 * `Signature\Validator`.
 *
 * - `envelope()` reads what correlates a response with its request, before
 *   anything in it is validated: every `InResponseTo` in the parsed document
 *   and whether it carries an encrypted assertion. The value is capped, decoded
 *   and parsed hardened, never schema-validated or verified; a value that
 *   cannot be read is `null`.
 * - `readResponse()` reads the response whole, for the connection's policy: the
 *   encoded value capped (`sso.saml2.max_response_bytes`) before it is decoded,
 *   the decoded XML capped (`max_xml_bytes`), parsed and schema-validated
 *   against the protocol schema with no `ID` repeated, then `ResponseReader`'s
 *   structure, signature and decryption rules. Either a `ReadResult` with the
 *   response, every signature in it verified with a certificate the connection
 *   trusts, or one refused with a reason and the rule that refused it.
 *
 * The posted value is HTTP-POST binding only: base64, never inflated (SSO-5.3).
 * Nothing here logs, reports or keeps what it read; a refusal's detail is the
 * package's own word for the rule, never the message. It holds the parser, the
 * reader and the limits, none of which keeps anything between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SamlAdapter
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser  $parser
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\ResponseReader  $reader
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Limits  $limits
     */
    public function __construct(

        /** Decodes and parses each document. */
        private HardenedParser $parser,

        /** Reads a parsed response. */
        private ResponseReader $reader,

        /** The caps every message is held to. */
        private Saml2Limits $limits,
    ) {}

    /**
     * What correlates the posted response with its request, or `null` when it
     * cannot be read.
     *
     * @param  string  $encoded
     * @return ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Envelope
     *
     * @throws \InvalidArgumentException
     */
    public function envelope(#[\SensitiveParameter] string $encoded): ?Envelope
    {
        try {
            $document = $this->parser->load($this->parser->decode($encoded, $this->limits->maxResponseBytes()), $this->limits->maxXmlBytes());
        } catch (ReadFailure) {
            return null;
        }

        return new Envelope(ResponseReader::inResponseTo($document), ResponseReader::isEncrypted($document));
    }

    /**
     * The posted response, read and verified for the policy, or why not.
     *
     * @param  string  $encoded
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ResponsePolicy  $policy
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ReadResult
     *
     * @throws \InvalidArgumentException
     */
    public function readResponse(#[\SensitiveParameter] string $encoded, ResponsePolicy $policy): ReadResult
    {
        try {
            $xml      = $this->parser->decode($encoded, $this->limits->maxResponseBytes());
            $document = $this->parser->parse($xml, MessageKind::PROTOCOL, $this->limits->maxXmlBytes(), FailureReason::RESPONSE_INVALID);

            return ReadResult::read($this->reader->read($document, $policy, $this->limits->maxDecryptedBytes()));
        } catch (ReadFailure $failure) {
            return ReadResult::refused($failure->reason, $failure->detail);
        }
    }
}
