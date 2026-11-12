<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Enums;

/**
 * The steps of a completion; the cases' order is the order they run.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CompletionStep: string
{
    // The driver reads which request the response answers
    case CORRELATION = 'correlation';

    // The request is looked up and consumed, before any validation
    case CONSUMPTION = 'consumption';

    // The driver validates the response against the consumed request
    case VALIDATION = 'validation';

    // What the driver asked to record against replay is recorded once
    case REPLAY_RECORDING = 'replay_recording';

    // The result's link is resolved
    case LINK_RESOLUTION = 'link_resolution';

    // The connection must satisfy its tenant's enforcement
    case ENFORCEMENT = 'enforcement';

    // What the flow's purpose requires of the resolved link
    case PURPOSE_RULES = 'purpose_rules';

    // Linking by a verified domain reserves a link
    case DOMAIN_RESERVATION = 'domain_reservation';

    // A genuinely unlinked sign-in stops at the provisioning boundary
    case PROVISIONING = 'provisioning';

    // An unlinked sign-in ends unless unlinked handoffs are allowed
    case UNLINKED_DECISION = 'unlinked_decision';

    // The handoff code is issued
    case HANDOFF_ISSUANCE = 'handoff_issuance';

    /**
     * Whether the step runs in the completion's locked transaction.
     *
     * @return bool
     */
    public function isLocked(): bool
    {
        return match ($this) {
            self::CORRELATION, self::CONSUMPTION, self::VALIDATION => false,
            default                                                => true,
        };
    }

    /**
     * Whether the step runs again in the final continuation.
     *
     * @return bool
     */
    public function isInContinuation(): bool
    {
        return match ($this) {
            self::LINK_RESOLUTION, self::ENFORCEMENT, self::PURPOSE_RULES, self::UNLINKED_DECISION, self::HANDOFF_ISSUANCE => true,
            default                                                                                                        => false,
        };
    }
}
