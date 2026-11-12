<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;

/**
 * The authentication context a verified SAML assertion states, or why it is
 * refused, with the first broken rule answering.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthenticationRules
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The authentication context the assertion states, or why it is refused.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return \SineMacula\Laravel\Sso\Events\Enums\FailureReason|\SineMacula\Laravel\Sso\Results\AuthenticationContext
     *
     * @throws \InvalidArgumentException
     */
    public static function context(SamlAssertion $assertion, ValidationContext $context): AuthenticationContext|FailureReason
    {
        $statements = $assertion->authnStatements();

        if (count($statements) !== 1) {
            return FailureReason::RESPONSE_INVALID;
        }

        return self::refusal($statements[0], $context) ?? self::authenticationContext($statements[0]);
    }

    /**
     * Why the statement is refused, or `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement  $statement
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function refusal(AuthnStatement $statement, ValidationContext $context): ?FailureReason
    {
        return match (true) {
            !self::isStorable($statement)                      => FailureReason::RESPONSE_INVALID,
            !$context->hasStarted($statement->authnInstant())  => FailureReason::ASSERTION_EXPIRED,
            !self::isWithinMaximumAge($statement, $context)    => FailureReason::AUTHENTICATION_EXPIRED,
            !self::isSinceRequestStarted($statement, $context) => FailureReason::AUTHENTICATION_EXPIRED,
            !self::isRequiredClass($statement, $context)       => FailureReason::AUTHENTICATION_CONTEXT_MISMATCH,
            self::hasSessionEnded($statement, $context)        => FailureReason::AUTHENTICATION_EXPIRED,
            default                                            => null,
        };
    }

    /**
     * Whether the session index and class fit the authentication context.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement  $statement
     * @return bool
     */
    private static function isStorable(AuthnStatement $statement): bool
    {
        return self::isStorableText($statement->sessionIndex()) && self::isStorableText($statement->contextClassRef());
    }

    /**
     * Whether the text is absent, or non-empty and within the cap.
     *
     * @param  ?string  $text
     * @return bool
     */
    private static function isStorableText(?string $text): bool
    {
        return $text === null || ($text !== '' && strlen($text) <= AuthenticationContext::MAX_VALUE_LENGTH);
    }

    /**
     * Whether the authentication is within the maximum age plus the skew, if
     * one is set.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement  $statement
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isWithinMaximumAge(AuthnStatement $statement, ValidationContext $context): bool
    {
        $maximum = $context->options->maxAuthenticationAgeSeconds;

        return $maximum === null || $statement->authnInstant() >= $context->now->subSeconds($maximum + $context->skew);
    }

    /**
     * Whether a reauthentication is no earlier than the request's start less
     * the skew.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement  $statement
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isSinceRequestStarted(AuthnStatement $statement, ValidationContext $context): bool
    {
        $start = $context->reauthenticationStart();

        return $start === null || $statement->authnInstant() >= $start->subSeconds($context->skew);
    }

    /**
     * Whether the class is exactly one the connection requires, if any.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement  $statement
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isRequiredClass(AuthnStatement $statement, ValidationContext $context): bool
    {
        $required = $context->options->listOf(Saml2Setting::REQUESTED_AUTHN_CONTEXT);

        return $required === [] || in_array($statement->contextClassRef(), $required, true);
    }

    /**
     * Whether the provider session's deadline has passed; no skew applies.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement  $statement
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function hasSessionEnded(AuthnStatement $statement, ValidationContext $context): bool
    {
        $deadline = $statement->sessionNotOnOrAfter();

        return $deadline !== null && $deadline <= $context->now;
    }

    /**
     * The authentication context the statement states.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\AuthnStatement  $statement
     * @return \SineMacula\Laravel\Sso\Results\AuthenticationContext
     *
     * @throws \InvalidArgumentException
     */
    private static function authenticationContext(AuthnStatement $statement): AuthenticationContext
    {
        return new AuthenticationContext(
            authenticatedAt: $statement->authnInstant(),
            contextClass: $statement->contextClassRef(),
            providerSessionId: $statement->sessionIndex(),
            providerSessionDeadline: $statement->sessionNotOnOrAfter(),
        );
    }
}
