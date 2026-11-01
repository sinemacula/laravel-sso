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
 * 4. `link_resolution`, then every later step, run in one transaction on the
 *    storage connection with the connection's row and the request's row locked,
 *    refusing first if either changed since consumption (the connection
 *    disabled or no longer usable, the request voided by a trust change): the
 *    result's link is resolved through the linking contract.
 * 5. `enforcement`: the connection must satisfy its tenant's enforcement for
 *    the application, and its version is kept for the handoff.
 * 6. `domain_reservation`: linking by a verified domain reserves a link
 *    (SSO-8.8); a seam that passes every result on until it is built.
 * 7. `provisioning`: an unlinked `sign_in` result holding no reservation is
 *    offered for provisioning (SSO-8.6); a seam that passes every result on
 *    until it is built.
 * 8. `unlinked_decision`: an unlinked `sign_in` result ends in `unlinked`,
 *    unless the application allows unlinked handoffs.
 * 9. `handoff_issuance`: the application policy is asked again, then the
 *    handoff issuer issues the code.
 *
 * An unsolicited SAML response consumes no request: re-initiation answers it at
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

    // The result's link is resolved
    case LINK_RESOLUTION = 'link_resolution';

    // The connection must satisfy its tenant's enforcement
    case ENFORCEMENT = 'enforcement';

    // Linking by a verified domain reserves a link (SSO-8.8)
    case DOMAIN_RESERVATION = 'domain_reservation';

    // An unlinked sign-in is offered for provisioning (SSO-8.6)
    case PROVISIONING = 'provisioning';

    // An unlinked sign-in ends unless unlinked handoffs are allowed
    case UNLINKED_DECISION = 'unlinked_decision';

    // The handoff code is issued
    case HANDOFF_ISSUANCE = 'handoff_issuance';

    /**
     * Whether the step runs in the completion's locked transaction: from link
     * resolution on.
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
}
