<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How the SAML adapter read a response (SSO-6.1 to SSO-6.3, SSO-6.7, SSO-6.8,
 * SSO-6.11): read, with the response it parsed and verified, or refused with a
 * reason and a detail.
 *
 * The detail is the package's own words for which rule refused the response
 * (`schema`, `duplicate_id`, `signature_policy`, say), for a log through the
 * sanitising logger; it never quotes the message, a value the provider sent or
 * a library's exception message. A decryption failure has one detail whatever
 * failed, so nothing distinguishes one cause from another (SSO-6.7).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReadResult
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?string  $detail
     */
    private function __construct(

        /** The response, for one read. */
        public ?SamlResponse $response,

        /** Why it was refused, for one refused. */
        public ?FailureReason $reason,

        /** Which rule refused it, in the package's own words, for one refused. */
        public ?string $detail,
    ) {}

    /**
     * The response was parsed and every signature in it verified.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @return self
     */
    public static function read(SamlResponse $response): self
    {
        return new self($response, null, null);
    }

    /**
     * The response was refused, for the reason, by the rule named.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return self
     */
    public static function refused(FailureReason $reason, string $detail): self
    {
        return new self(null, $reason, $detail);
    }

    /**
     * Whether the response was read.
     *
     * @return bool
     */
    public function isRead(): bool
    {
        return $this->response !== null;
    }
}
