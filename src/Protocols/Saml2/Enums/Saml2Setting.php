<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Enums;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The settings of a SAML 2.0 connection, by stored name. Values are stable once
 * released: never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Saml2Setting: string
{
    // The `Issuer` every response and assertion must carry
    case IDP_ENTITY_ID = 'idp_entity_id';

    // The identity provider's single sign-on URL
    case SSO_URL = 'sso_url';

    // HTTP-Redirect or HTTP-POST for the `AuthnRequest`
    case SSO_BINDING = 'sso_binding';

    // Where the subject comes from: the `NameID` or an attribute
    case SUBJECT_SOURCE = 'subject_source';

    // The attribute holding a stable identifier, when that is the source
    case SUBJECT_ATTRIBUTE = 'subject_attribute';

    // The NameID format requested and accepted; never `transient`
    case NAME_ID_FORMAT = 'name_id_format';

    // Whether `AuthnRequest`s are signed with the SP signing key
    case SIGN_AUTHN_REQUESTS = 'sign_authn_requests';

    // Whether the assertion must carry its own signature
    case WANT_ASSERTIONS_SIGNED = 'want_assertions_signed';

    // Whether assertions must be encrypted
    case REQUIRE_ENCRYPTED_ASSERTIONS = 'require_encrypted_assertions';

    // The signature algorithms accepted
    case SIGNATURE_ALGORITHMS = 'signature_algorithms';

    // The key transport and data encryption algorithms accepted
    case ENCRYPTION_ALGORITHMS = 'encryption_algorithms';

    // Whether every `AuthnRequest` asks for fresh authentication
    case FORCE_AUTHN = 'force_authn';

    // Authentication context classes requested exactly and required back
    case REQUESTED_AUTHN_CONTEXT = 'requested_authn_context';

    // The oldest the `AuthnInstant` may be, in seconds; none by default
    case MAX_AUTHENTICATION_AGE_SECONDS = 'max_authentication_age_seconds';

    // Whether an unsolicited response is re-initiated
    case IDP_INITIATED = 'idp_initiated';

    // The start URL an unsolicited response is re-initiated through
    case IDP_INITIATED_START_URL = 'idp_initiated_start_url';

    // The HTTPS URL the identity provider's metadata is fetched from
    case METADATA_URL = 'metadata_url';

    // Whether metadata refreshes on a schedule; unset means on exactly while
    // there is a `metadata_url` and a metadata signing anchor
    case METADATA_REFRESH = 'metadata_refresh';

    /**
     * The operation whose freshness a change needs, or `null` when the change
     * never widens or redirects access.
     *
     * @return ?\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    public function freshness(): ?FreshnessOperation
    {
        return match ($this) {
            self::SIGN_AUTHN_REQUESTS, self::FORCE_AUTHN       => null,
            self::IDP_INITIATED, self::IDP_INITIATED_START_URL => FreshnessOperation::CONNECTION_IDP_INITIATED,
            default                                            => FreshnessOperation::CONNECTION_TRUST,
        };
    }

    /**
     * Whether a change may alter what existing subjects mean.
     *
     * @return bool
     */
    public function altersSubject(): bool
    {
        return in_array($this, [self::IDP_ENTITY_ID, self::SUBJECT_SOURCE, self::SUBJECT_ATTRIBUTE, self::NAME_ID_FORMAT], true);
    }

    /**
     * The names of the settings that alter what existing subjects mean.
     *
     * @return list<string>
     */
    public static function subjectNames(): array
    {
        return array_values(array_map(
            static fn (self $setting): string => $setting->value,
            array_filter(self::cases(), static fn (self $setting): bool => $setting->altersSubject()),
        ));
    }
}
