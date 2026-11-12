<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlConditions;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;

/**
 * The `Conditions` and `IssueInstant` rules, checked in order with the first
 * broken one answering.
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
     * Why the conditions or either `IssueInstant` refuse the response, or
     * `null`.
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
     * Why the conditions refuse the assertion, or `null`. `OneTimeUse` and
     * `ProxyRestriction` pass, as no assertion is kept or passed on.
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
     * Whether now is within `NotBefore` and `NotOnOrAfter`; an absent bound
     * holds.
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
     * Whether every audience restriction names the service provider; an empty
     * one names nothing.
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
     * Why either `IssueInstant` refuses the response, or `null`.
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
