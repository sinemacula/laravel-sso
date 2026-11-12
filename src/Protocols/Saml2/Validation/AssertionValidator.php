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
 * Validates a posted SAML response for both the solicited and unsolicited
 * profiles; which applies depends only on whether a consumed request is given.
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

    /** @var string The format an absent `NameFormat` means (SAML 2.0 Core 2.7.3.1). */
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

        /** The package's sanitising logger. */
        private LoggerInterface $logger,
    ) {}

    /**
     * The linking email, or `null`. An encrypted attribute makes "present once"
     * unknowable, so it gives none.
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
     * Validate the posted response; with no consumed request, by the
     * unsolicited profile.
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
     * Log which rule refused the read and refuse with its reason.
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
     * Judge the response by its profile, then by every success rule.
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
     * Why the profile refuses the response, or `null`. Any `InResponseTo` makes
     * a response solicited.
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
     * Why an unsuccessful response is refused: an envelope rule, else
     * `provider_error` with its status logged.
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
     * Log the status codes and message; the logger sanitises the message, which
     * never goes in an event.
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
     * Hold a successful response to every rule, then answer its claims and
     * replay record.
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
     * The claims and replay record, or why the subject or authentication is
     * refused.
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
     * The linking attribute's `Name` and `NameFormat`, while linking is on and
     * acknowledged.
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
     * The linking email, or `null` when the value is no address.
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
     * The organisation from the named claim attribute, never the email domain;
     * `null` if absent or too long.
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
     * The single non-empty value of the one attribute of the name in exactly
     * the format. A same-named attribute in another format refuses it.
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
     * The string attribute values by name, in order; repeated names merge and
     * non-text values are dropped.
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
