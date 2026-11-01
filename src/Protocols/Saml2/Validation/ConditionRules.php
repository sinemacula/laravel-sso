<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;

/**
 * The rules of a SAML assertion's `Conditions` and of the response's and the
 * assertion's `IssueInstant` (SSO-6.4, SSO-6.5, SAML 2.0 Core §2.5), in this
 * order, the first broken answering:
 *
 * 1. `NotBefore`, when present, is not after now plus the skew, and now is
 *    before `NotOnOrAfter`, when present, plus the skew, or
 *    `assertion_expired`;
 * 2. every `AudienceRestriction` names the connection's service provider
 *    entity id, compared exactly, since each is a condition of its own that
 *    must hold; an empty one names nothing, so it is refused; or
 *    `audience_mismatch`;
 * 3. `OneTimeUse` and `ProxyRestriction` are accepted, since the package never
 *    keeps or passes on an assertion; any other condition is one the package
 *    does not understand, and is `condition_unsupported`;
 * 4. the response's and the assertion's `IssueInstant` are each not after now
 *    plus the skew, and no older than `sso.saml2.issue_instant_max_age_seconds`
 *    plus the skew, or `assertion_expired`.
 *
 * An assertion without `Conditions` holds the first three. Nothing here keeps
 * anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConditionRules
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the assertion's conditions or either `IssueInstant` refuse the
     * response, or `null` when every rule holds.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function refusal(SamlResponse $response, SamlAssertion $assertion, ValidationContext $context): ?FailureReason
    {
        $conditions = $assertion->conditions();
        $refusal    = $conditions === null ? null : self::conditionsRefusal($conditions, $context);

        return $refusal ?? self::issueInstantRefusal($response, $assertion, $context);
    }

    /**
     * Why the conditions refuse the assertion, or `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions  $conditions
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function conditionsRefusal(SamlConditions $conditions, ValidationContext $context): ?FailureReason
    {
        return match (true) {
            !self::isWithinValidity($conditions, $context)     => FailureReason::ASSERTION_EXPIRED,
            !self::isForServiceProvider($conditions, $context) => FailureReason::AUDIENCE_MISMATCH,
            $conditions->otherConditions() !== []              => FailureReason::CONDITION_UNSUPPORTED,
            default                                            => null,
        };
    }

    /**
     * Whether now is within the conditions' `NotBefore` and `NotOnOrAfter`,
     * each with the skew, a bound that is absent holding.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions  $conditions
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isWithinValidity(SamlConditions $conditions, ValidationContext $context): bool
    {
        $notBefore = $conditions->notBefore();
        $started   = $notBefore === null || $context->hasStarted($notBefore);

        $notOnOrAfter = $conditions->notOnOrAfter();
        $ongoing      = $notOnOrAfter === null || $context->isBefore($notOnOrAfter);

        return $started && $ongoing;
    }

    /**
     * Whether every audience restriction names the service provider.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions  $conditions
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isForServiceProvider(SamlConditions $conditions, ValidationContext $context): bool
    {
        foreach ($conditions->audienceRestrictions() as $audiences) {
            if (!in_array($context->serviceProviderEntityId, $audiences, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Why the response's or the assertion's `IssueInstant` refuses the
     * response, or `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function issueInstantRefusal(SamlResponse $response, SamlAssertion $assertion, ValidationContext $context): ?FailureReason
    {
        $fresh = $context->isFresh($response->issueInstant()) && $context->isFresh($assertion->issueInstant());

        return $fresh ? null : FailureReason::ASSERTION_EXPIRED;
    }
}
