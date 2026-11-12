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
 * The SAML driver's one entry for reading a posted `SAMLResponse`. Only this
 * namespace may call the SAML libraries; an architecture test holds that.
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
     * What correlates the response with its request, read without schema or
     * signature checks; `null` when unreadable.
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
     * The posted HTTP-POST response, capped, schema-validated and verified for
     * the policy, or why not.
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
