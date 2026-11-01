<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;

/**
 * The rules of a SAML response's envelope and its assertion's provenance
 * (SSO-6.2, SSO-6.4, SSO-6.8), in this order, the first broken answering:
 *
 * 1. the response's `Issuer`, when present, and the assertion's `Issuer` each
 *    equal the connection's identity provider entity id, compared exactly, or
 *    `issuer_mismatch`;
 * 2. the response's `Destination` equals the connection's assertion consumer
 *    service URL exactly, and is present when the response is signed, or
 *    `recipient_mismatch`;
 * 3. a connection that requires encrypted assertions refuses a plain one with
 *    `encryption_required`, so a response cannot downgrade;
 * 4. a connection that wants assertions signed (the default) refuses an
 *    assertion that carries no signature of its own with `signature_invalid`,
 *    even when the response's signature covers it.
 *
 * The adapter has already verified every signature present and refused an
 * assertion no verified signature covers; these rules judge only what was
 * verified. An unsuccessful response is held to the first two, of its own
 * envelope (`envelopeRefusal()`). Nothing here keeps anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResponseRules
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why a successful response and its assertion are refused, or `null` when
     * every rule holds.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function refusal(SamlResponse $response, SamlAssertion $assertion, ValidationContext $context): ?FailureReason
    {
        return match (true) {
            !self::isResponseIssuer($response, $context)                 => FailureReason::ISSUER_MISMATCH,
            !$context->isIdentityProvider($assertion->issuer()->value()) => FailureReason::ISSUER_MISMATCH,
            !self::isDestination($response, $context)                    => FailureReason::RECIPIENT_MISMATCH,
            self::isPlainWhereEncryptionIsRequired($assertion, $context) => FailureReason::ENCRYPTION_REQUIRED,
            self::isUnsignedWhereSignatureIsWanted($assertion, $context) => FailureReason::SIGNATURE_INVALID,
            default                                                      => null,
        };
    }

    /**
     * Why a response's envelope alone is refused, as an unsuccessful response
     * is judged: its `Issuer` and `Destination`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function envelopeRefusal(SamlResponse $response, ValidationContext $context): ?FailureReason
    {
        return match (true) {
            !self::isResponseIssuer($response, $context) => FailureReason::ISSUER_MISMATCH,
            !self::isDestination($response, $context)    => FailureReason::RECIPIENT_MISMATCH,
            default                                      => null,
        };
    }

    /**
     * Whether the response's `Issuer` is absent or the identity provider's.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isResponseIssuer(SamlResponse $response, ValidationContext $context): bool
    {
        $issuer = $response->issuer();

        return $issuer === null || $context->isIdentityProvider($issuer->value());
    }

    /**
     * Whether the response's `Destination` is the assertion consumer service,
     * or absent from a response that is not signed.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isDestination(SamlResponse $response, ValidationContext $context): bool
    {
        $destination = $response->destination();

        return $destination === null ? !$response->isSigned() : $destination === $context->assertionConsumerService;
    }

    /**
     * Whether the connection requires encrypted assertions and the assertion
     * arrived plain.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isPlainWhereEncryptionIsRequired(SamlAssertion $assertion, ValidationContext $context): bool
    {
        return $context->options->isOn(Saml2Setting::REQUIRE_ENCRYPTED_ASSERTIONS) && !$assertion->isEncrypted();
    }

    /**
     * Whether the connection wants assertions signed and the assertion carries
     * no signature of its own.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isUnsignedWhereSignatureIsWanted(SamlAssertion $assertion, ValidationContext $context): bool
    {
        return $context->options->isOn(Saml2Setting::WANT_ASSERTIONS_SIGNED) && !$assertion->isSigned();
    }
}
