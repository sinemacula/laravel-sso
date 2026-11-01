<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\ReplayRecord;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;

/**
 * What a validated SAML assertion is recorded as against replay (SSO-6.6, SAML
 * 2.0 Profiles §4.1.4.5): its id, scoped by the connection and its issuer, so
 * one tenant's identity provider cannot poison another's, until the last moment
 * any rule would still accept it. That is the earliest of:
 *
 * - the `Conditions`' `NotOnOrAfter` plus the skew, when present;
 * - the chosen bearer confirmation's `NotOnOrAfter` plus the skew (the latest
 *   of the confirmations that could be chosen, `BearerConfirmations`);
 * - the assertion's `IssueInstant` plus `issue_instant_max_age_seconds` plus
 *   the skew, which bounds every record.
 *
 * Every bound is read from inside the assertion its signature covers, never
 * from the response's envelope, which a replay may carry afresh. Nothing is
 * recorded here: the completion records it under the connection's lock once the
 * response is validated (`Completion\Stages\RecordReplay`), so an invalid
 * assertion records nothing, and refuses a record whose expiry is not after its
 * own now.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReplayWindow
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The replay record of the assertion accepted by the confirmation.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation  $confirmation
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return \SineMacula\Laravel\Sso\Protocols\ReplayRecord
     *
     * @throws \InvalidArgumentException
     */
    public static function record(SamlAssertion $assertion, SubjectConfirmation $confirmation, ValidationContext $context): ReplayRecord
    {
        return ReplayRecord::samlAssertion($context->connectionId, $assertion->issuer()->value(), $assertion->id(), self::until($assertion, $confirmation, $context));
    }

    /**
     * The last moment any rule would still accept the assertion.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation  $confirmation
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return \Carbon\CarbonImmutable
     */
    public static function until(SamlAssertion $assertion, SubjectConfirmation $confirmation, ValidationContext $context): CarbonImmutable
    {
        $until = $context->freshUntil($assertion->issueInstant());

        foreach ([$assertion->conditions()?->notOnOrAfter(), $confirmation->notOnOrAfter()] as $notOnOrAfter) {

            if ($notOnOrAfter === null) {
                continue;
            }

            $bound = $context->skewed($notOnOrAfter);
            $until = $bound < $until ? $bound : $until;
        }

        return $until;
    }
}
