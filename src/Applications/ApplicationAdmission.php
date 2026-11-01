<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * Whether a flow may run for the application a request names (SSO-5.1,
 * SSO-9.2): admitted, with the registered application, or refused with
 * `application_not_allowed`, whether the name is registered for no application
 * or the application does not allow sign-in through an external provider, so a
 * refusal says nothing of which.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApplicationAdmission
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The registered application, for an admitted one. */
        public ?Application $application,

        /** Why it was refused, for a refused one. */
        public ?FailureReason $reason,
    ) {}

    /**
     * The application is registered and allows sign-in through an external
     * provider.
     *
     * @param  \SineMacula\Laravel\Sso\Applications\Application  $application
     * @return self
     */
    public static function admitted(Application $application): self
    {
        return new self($application, null);
    }

    /**
     * The application is unknown or does not allow sign-in through an external
     * provider.
     *
     * @return self
     */
    public static function notAllowed(): self
    {
        return new self(null, FailureReason::APPLICATION_NOT_ALLOWED);
    }

    /**
     * Whether the application was admitted.
     *
     * @return bool
     */
    public function isAdmitted(): bool
    {
        return $this->application !== null;
    }

    /**
     * Whether the application was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->reason !== null;
    }
}
