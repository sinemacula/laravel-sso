<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a driver started an authorisation request (SSO-5.1): with the navigation
 * that sends the browser to the identity provider and what the request must
 * keep to complete it (the SAML request id for `InResponseTo`, the expected
 * issuer), or refused with a reason.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Start
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @param  array<string, string>  $requestData
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** Where the browser goes, for a started request. */
        public ?Navigation $navigation,

        /** What the authorisation request keeps to complete, by name, for a started request. */
        public array $requestData,

        /** Why the request could not start, for a refused one. */
        public ?FailureReason $reason,
    ) {}

    /**
     * The request started: the browser goes where the navigation leads, and the
     * authorisation request keeps the data given.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Navigation  $navigation
     * @param  array<string, string>  $requestData
     * @return self
     */
    public static function navigate(Navigation $navigation, array $requestData = []): self
    {
        return new self($navigation, $requestData, null);
    }

    /**
     * The request could not start, for the reason given.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, [], $reason);
    }

    /**
     * Whether the request started.
     *
     * @return bool
     */
    public function isNavigating(): bool
    {
        return $this->navigation !== null;
    }

    /**
     * Whether the request was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->reason !== null;
    }
}
