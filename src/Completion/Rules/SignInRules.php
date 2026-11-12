<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Rules;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\Enums\LinkResolutionStatus;

/**
 * What a `sign_in` requires of its link at completion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInRules
{
    /**
     * Why the state may not go on as a `sign_in`, or `null` when it may.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public function refusal(CompletionState $state): ?FailureReason
    {
        return match ($state->resolution?->status) {
            LinkResolutionStatus::SUSPENDED     => FailureReason::LINK_SUSPENDED,
            LinkResolutionStatus::SCOPE_UNKNOWN => FailureReason::PRINCIPAL_SCOPE_UNKNOWN,
            LinkResolutionStatus::RESERVED      => FailureReason::LINK_RESERVED,
            default                             => null,
        };
    }
}
