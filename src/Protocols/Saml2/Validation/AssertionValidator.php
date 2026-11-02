<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Clock\ClockSkew;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\EndpointResolver;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlAdapter;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums\ValidationProfile;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ReadResult;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAttribute;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Limits;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedClaims;

/**
 * Validates a posted SAML response (SSO-6.2 to SSO-6.11): the one core both the
 * solicited path (`ResponseValidator`, with the consumed request) and the
 * unsolicited profile (with none, SSO-5.8) share. Which profile's rules apply
 * depends only on whether a consumed request is given.
 *
 * In this order, the first refusal answering:
 *
 * 1. The posted `SAMLResponse` is read through the SAML adapter, with the
 *    connection's policy (`ResponsePolicies`): parsed hardened, its structure
 *    checked, every signature verified with a trusted certificate and its
 *    assertion decrypted. A refused read is refused with the adapter's
 *    reason; the rule that refused it is logged, in the package's own words.
 * 2. The profile: an unsuccessful response (a status other than success) is
 *    refused with `provider_error` once its `Issuer` and `Destination` hold and
 *    its `InResponseTo` is the consumed request's (any of which refuses it
 *    first), and its status codes and sanitised `StatusMessage` are logged,
 *    never shown or put in an event (SSO-6.9, SSO-5.7). A solicited response
 *    with no consumed request, and an unsolicited one with one, are
 *    `request_unknown`: an `InResponseTo` anywhere is never unsolicited.
 * 3. `ResponseRules`: issuers, destination, encryption and the assertion's own
 *    signature.
 * 4. `ConditionRules`: the conditions, audiences and `IssueInstant`s.
 * 5. `BearerConfirmations`: the request answered and the one bearer
 *    confirmation the assertion is accepted by.
 * 6. `SubjectRules`: the subject, encoded by `SubjectEncoding`.
 * 7. `AuthenticationRules`: the authentication context.
 *
 * A response that passes is verified with its claims (the identity provider's
 * entity id, the subject and its NameID format, the attributes of its
 * assertion's attribute statements by name, each a list of its string values in
 * order, the authentication context and the linking email) and the replay
 * record of its assertion (`ReplayWindow`), which the completion records under
 * the connection's lock; nothing is recorded here.
 *
 * The linking email (SSO-8.8) is built only while linking by a verified domain
 * is on, by its feature and its connection, with its acknowledgement, and only
 * from the one attribute the connection names by exact `Name` and `NameFormat`,
 * present once with exactly one non-empty string value: an attribute of that
 * `Name` in another `NameFormat`, a second one, a second value, an empty value
 * or a value that is not simple text gives none, an encrypted attribute leaves
 * "present once" unknowable and gives none, and nothing falls back to a
 * `FriendlyName` or an email-format `NameID`. An absent `NameFormat` is
 * `unspecified`, as SAML 2.0 Core 2.7.3.1 says. The organisation comes from the
 * attribute the connection names as its claim, under the same exactness, never
 * from the email's domain or the mapped attributes.
 *
 * Every time rule reads one instant, the clock's now once the response is read,
 * with the skew of `sso.clock.skew_seconds`. Nothing of the response is ever
 * logged, reported or kept: a log names the connection, the request's public
 * reference and the package's own words, with the status message sanitised. It
 * holds the adapter, the policies, the endpoint resolver, the clock, the limits
 * and the sanitising logger, none of which keeps anything between calls
 * (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AssertionValidator
{
    /** @var string The posted field that carries the response. */
    public const string FIELD = 'SAMLResponse';

    /** @var string What an attribute with no `NameFormat` is named under (SAML 2.0 Core 2.7.3.1). */
    private const string UNSPECIFIED_NAME_FORMAT = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\SamlAdapter  $adapter
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ResponsePolicies  $policies
     * @param  \SineMacula\Laravel\Sso\Contracts\EndpointResolver  $endpoints
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Limits  $limits
     * @param  \Psr\Log\LoggerInterface  $logger
     */
    public function __construct(

        /** Reads the response; the only way to the SAML library. */
        private SamlAdapter $adapter,

        /** Builds the connection's response policy. */
        private ResponsePolicies $policies,

        /** The connection's assertion consumer service and entity id. */
        private EndpointResolver $endpoints,

        /** The clock every time rule reads. */
        private Clock $clock,

        /** The `IssueInstant` maximum age. */
        private Saml2Limits $limits,

        /** Logs a refused read and an unsuccessful status: the package's sanitising logger. */
        private LoggerInterface $logger,
    ) {}

    /**
     * The linking email the assertion gives under the connection's linking
     * settings, or `null`: with linking off or not acknowledged, with no
     * attribute named, or when the named attribute is not exactly as it must
     * be.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  array<string, bool|int|string|null>  $linking
     * @return ?\SineMacula\Laravel\Sso\Results\LinkingEmail
     */
    public static function linkingEmail(SamlAssertion $assertion, array $linking): ?LinkingEmail
    {
        $named = self::namedAttribute($linking);

        if ($named === null || $assertion->encryptedAttributes() !== 0) {
            return null;
        }

        $email = self::soleValue($assertion, $named[0], $named[1]);

        return $email === null ? null : self::builtEmail($email, self::organization($assertion, $linking['organization_claim'] ?? null, $named[1]));
    }

    /**
     * Validate the posted response for the connection, against the consumed
     * request, or by the unsolicited profile when none is given.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\CompletionRequest  $request
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     */
    public function validate(SsoConnection $connection, Saml2Options $options, CompletionRequest $request, ?ConsumedRequest $consumed): Completion
    {
        $encoded = $request->body()[self::FIELD] ?? null;

        if (!is_string($encoded) || $encoded === '') {
            return Completion::refused(FailureReason::RESPONSE_INVALID);
        }

        $read     = $this->adapter->readResponse($encoded, $this->policies->policy($connection, $options));
        $response = $read->response;

        if ($response === null) {
            return $this->refusedRead($read, $connection, $consumed);
        }

        return $this->judge($response, $this->context($connection, $options, $consumed), $connection->getLinkingSettings());
    }

    /**
     * Log which rule refused the read, in the package's own words, and refuse
     * the response with its reason.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\ReadResult  $read
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     */
    private function refusedRead(ReadResult $read, SsoConnection $connection, ?ConsumedRequest $consumed): Completion
    {
        $reason = $read->reason ?? FailureReason::RESPONSE_INVALID;

        $this->logger->notice('sso.saml2.response_refused', [
            'connection_id'     => $connection->getConnectionId(),
            'request_reference' => $consumed?->reference->value,
            'reason'            => $reason->value,
            'detail'            => $read->detail,
        ]);

        return Completion::refused($reason);
    }

    /**
     * What the response is judged against, now.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options  $options
     * @param  ?\SineMacula\Laravel\Sso\Protocols\ConsumedRequest  $consumed
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext
     *
     * @throws \InvalidArgumentException
     */
    private function context(SsoConnection $connection, Saml2Options $options, ?ConsumedRequest $consumed): ValidationContext
    {
        $endpoints = $this->endpoints->endpoints($connection);

        return new ValidationContext(
            $connection->getConnectionId(),
            $options,
            $endpoints->assertionConsumerService,
            $endpoints->entityId,
            $this->clock->now(),
            ClockSkew::seconds(),
            $this->limits->issueInstantMaxAgeSeconds(),
            $consumed,
        );
    }

    /**
     * Judge the read response by its profile, then by every rule of a
     * successful response.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @param  array<string, bool|int|string|null>  $linking
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     */
    private function judge(SamlResponse $response, ValidationContext $context, array $linking): Completion
    {
        $reason = $this->profileRefusal($response, $context);

        if ($reason !== null) {
            return Completion::refused($reason);
        }

        $assertion = $response->assertion();

        return $assertion === null ? Completion::refused(FailureReason::RESPONSE_INVALID) : self::verify($response, $assertion, $context, $linking);
    }

    /**
     * Why the response's profile refuses it, or `null` for a successful
     * response of the profile the consumed request, or its absence, calls for.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function profileRefusal(SamlResponse $response, ValidationContext $context): ?FailureReason
    {
        return match ($response->profile()) {
            ValidationProfile::UNSUCCESSFUL => $this->unsuccessful($response, $context),
            ValidationProfile::SOLICITED    => $context->isSolicited() ? null : FailureReason::REQUEST_UNKNOWN,
            ValidationProfile::UNSOLICITED  => $context->isSolicited() ? FailureReason::REQUEST_UNKNOWN : null,
            ValidationProfile::METADATA     => FailureReason::RESPONSE_INVALID,
        };
    }

    /**
     * Why an unsuccessful response is refused: its envelope's rule, or, once
     * they hold, `provider_error`, with its status logged sanitised.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private function unsuccessful(SamlResponse $response, ValidationContext $context): FailureReason
    {
        $reason = ResponseRules::envelopeRefusal($response, $context);

        if ($reason !== null) {
            return $reason;
        }

        if (!BearerConfirmations::isAnswer($response, $context)) {
            return FailureReason::REQUEST_MISMATCH;
        }

        $this->logStatus($response, $context);

        return FailureReason::PROVIDER_ERROR;
    }

    /**
     * Log the unsuccessful response's status codes and its status message,
     * which the logger sanitises as a diagnostic.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return void
     */
    private function logStatus(SamlResponse $response, ValidationContext $context): void
    {
        $status = $response->status();

        $this->logger->warning('sso.saml2.unsuccessful_status', [
            'connection_id'     => $context->connectionId,
            'request_reference' => $context->consumed?->reference->value,
            'status'            => $status->code(),
            'sub_status'        => $status->subCode(),
            'status_message'    => $status->message(),
        ]);
    }

    /**
     * Hold a successful response and its assertion to every rule, then answer
     * its claims and the replay record of its assertion.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @param  array<string, bool|int|string|null>  $linking
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     */
    private static function verify(SamlResponse $response, SamlAssertion $assertion, ValidationContext $context, array $linking): Completion
    {
        $reason = ResponseRules::refusal($response, $assertion, $context) ?? ConditionRules::refusal($response, $assertion, $context);

        if ($reason !== null) {
            return Completion::refused($reason);
        }

        $confirmation = BearerConfirmations::chosen($response, $assertion, $context);

        return $confirmation instanceof FailureReason ? Completion::refused($confirmation) : self::claimed($assertion, $confirmation, $context, $linking);
    }

    /**
     * The claims of the assertion's subject and authentication, and its replay
     * record, or why its subject or authentication is refused.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation  $confirmation
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @param  array<string, bool|int|string|null>  $linking
     * @return \SineMacula\Laravel\Sso\Protocols\Completion
     *
     * @throws \InvalidArgumentException
     */
    private static function claimed(SamlAssertion $assertion, SubjectConfirmation $confirmation, ValidationContext $context, array $linking): Completion
    {
        $subject = SubjectRules::subject($assertion, $context);

        if ($subject instanceof FailureReason) {
            return Completion::refused($subject);
        }

        $authentication = AuthenticationRules::context($assertion, $context);

        if ($authentication instanceof FailureReason) {
            return Completion::refused($authentication);
        }

        $email  = self::linkingEmail($assertion, $linking);
        $claims = new VerifiedClaims($assertion->issuer()->value(), $subject[0], $subject[1], self::attributes($assertion), $authentication, $email);

        return Completion::verified($claims, ReplayWindow::record($assertion, $confirmation, $context));
    }

    /**
     * The `Name` and `NameFormat` the connection names, while the feature and
     * its linking are on and acknowledged; `null` otherwise.
     *
     * @param  array<string, bool|int|string|null>  $linking
     * @return ?array{0: string, 1: string}
     */
    private static function namedAttribute(array $linking): ?array
    {
        $name   = $linking['saml_attribute']        ?? null;
        $format = $linking['saml_attribute_format'] ?? null;

        if (!Features::enabled(Feature::DOMAIN_LINKING) || ($linking['enabled'] ?? false) !== true || ($linking['acknowledged'] ?? false) !== true) {
            return null;
        }

        return is_string($name) && is_string($format) ? [$name, $format] : null;
    }

    /**
     * The linking email of the value and the organisation, or `null` when the
     * value is no address.
     *
     * @param  string  $email
     * @param  ?string  $organization
     * @return ?\SineMacula\Laravel\Sso\Results\LinkingEmail
     */
    private static function builtEmail(#[\SensitiveParameter] string $email, #[\SensitiveParameter] ?string $organization): ?LinkingEmail
    {
        try {
            return new LinkingEmail($email, LinkingEmailSource::SAML_ATTRIBUTE, $organization);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * The organisation the claim names under the format, or `null` when none is
     * named or it is not a string a result can hold.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  mixed  $claim
     * @param  string  $format
     * @return ?string
     */
    private static function organization(SamlAssertion $assertion, mixed $claim, string $format): ?string
    {
        $value = is_string($claim) ? self::soleValue($assertion, $claim, $format) : null;

        return $value !== null && strlen($value) <= LinkingEmail::MAX_ORGANIZATION_LENGTH ? $value : null;
    }

    /**
     * The one non-empty string value of the one attribute of the name, when it
     * is in exactly the format; `null` otherwise. Only `Name` selects it, so a
     * second attribute of the name in another format refuses it, and a
     * `FriendlyName` is never read.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  string  $name
     * @param  string  $format
     * @return ?string
     */
    private static function soleValue(SamlAssertion $assertion, string $name, string $format): ?string
    {
        $named = array_values(array_filter($assertion->attributes(), static fn (SamlAttribute $attribute): bool => $attribute->name() === $name));

        if (count($named) !== 1 || ($named[0]->nameFormat() ?? self::UNSPECIFIED_NAME_FORMAT) !== $format) {
            return null;
        }

        $values = $named[0]->values();

        return count($values) === 1 && $values[0] !== '' ? $values[0] : null;
    }

    /**
     * The attributes of the assertion's attribute statements, by name, each the
     * list of its string values in order; an attribute named twice holds both
     * lists' values, and a value that is not simple text is left out.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @return array<string, list<string>>
     */
    private static function attributes(SamlAssertion $assertion): array
    {
        $attributes = [];

        foreach ($assertion->attributes() as $attribute) {

            $name = $attribute->name();

            $attributes[$name] = [...($attributes[$name] ?? []), ...array_values(array_filter($attribute->values(), is_string(...)))];
        }

        return $attributes;
    }
}
