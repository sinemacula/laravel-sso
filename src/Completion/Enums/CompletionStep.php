<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Enums;

/**
 * The steps of a completion, in the fixed order they run (SSO-5.6, SSO-8.6):
 * the cases' order is the pipeline's order, and a stage is registered for each.
 *
 * 1. `correlation`: the driver reads which request the response answers, and
 *    nothing else, outside any transaction.
 * 2. `consumption`: the pipeline looks the request up on the write connection
 *    and consumes it through the single-use store, in a transaction of its own,
 *    before anything is validated: the only place a request is consumed, so it
 *    is consumed once whether the response then passes or fails.
 * 3. `validation`: the driver validates the response against the consumed
 *    request, outside any transaction (an OIDC token request is a fetch).
 * 4. `replay_recording`, then every later step, run in one transaction on the
 *    storage connection with the connection's row and the request's row locked,
 *    refusing first if either changed since consumption (the connection
 *    disabled or no longer usable, the request voided by a trust change): what
 *    the driver asked to record against replay (a SAML assertion's id, by
 *    connection and issuer, SSO-6.6) is recorded through the single-use store,
 *    a repeat refused with `replayed`, before any downstream effect.
 * 5. `link_resolution`: the result's link is resolved through the linking
 *    contract.
 * 6. `enforcement`: the connection must satisfy its tenant's enforcement for
 *    the application, and its version is kept for the handoff.
 * 7. `purpose_rules`: what the flow's purpose requires of the resolved link: a
 *    suspended or reserved subject ends a `sign_in`; a `link` needs an eligible
 *    identity and a subject not held by another; a `reauthenticate` needs a
 *    result that resolves to the identity it was started for and states an
 *    authentication time inside the window (`Completion\Rules`, SSO-5.10).
 * 8. `domain_reservation`: linking by a verified domain reserves a link
 *    (SSO-8.8).
 * 9. `provisioning`: a genuinely unlinked `sign_in` result holding no
 *    reservation stops the transaction at the provisioning boundary (SSO-8.6):
 *    what it recorded commits, the unlinked-result event is dispatched with no
 *    package transaction open, and a final continuation takes the locks again.
 * 10. `unlinked_decision`: an unlinked `sign_in` result ends in `unlinked`,
 *    unless the application allows unlinked handoffs.
 * 11. `handoff_issuance`: the application policy is asked again, then the
 *    handoff issuer issues the code.
 *
 * The final continuation runs only the steps `isInContinuation()` names: it
 * never records replay again, selects a domain or offers provisioning again. An
 * unsolicited SAML response consumes no request: re-initiation answers it at
 * `correlation`.
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

    // Linking by a verified domain reserves a link (SSO-8.8)
    case DOMAIN_RESERVATION = 'domain_reservation';

    // A genuinely unlinked sign-in stops at the provisioning boundary (SSO-8.6)
    case PROVISIONING = 'provisioning';

    // An unlinked sign-in ends unless unlinked handoffs are allowed
    case UNLINKED_DECISION = 'unlinked_decision';

    // The handoff code is issued
    case HANDOFF_ISSUANCE = 'handoff_issuance';

    /**
     * Whether the step runs in the completion's locked transaction: from the
     * replay recording on.
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
     * Whether the step runs again in the final continuation, after the
     * provisioning boundary.
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
