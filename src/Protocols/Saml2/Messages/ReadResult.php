<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * The SAML adapter's verdict on a response: read and verified, or refused with
 * a reason and the refusing rule's name, which never quotes the message.
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

        /** Which rule refused it, for one refused. */
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
