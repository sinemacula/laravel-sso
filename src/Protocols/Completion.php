<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a driver judged the identity provider's response to an authorisation
 * request (SSO-5.6, SSO-6, SSO-7).
 *
 * Until the completion pipeline (BL-34) adds the verified outcome, carrying the
 * verified result, every completion is refused with a reason: no driver can yet
 * produce a result, and none passes for one.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Completion
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** Why the response was refused. */
        public FailureReason $reason,
    ) {}

    /**
     * The response was refused, for the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self($reason);
    }

    /**
     * Whether the response was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return true;
    }
}
