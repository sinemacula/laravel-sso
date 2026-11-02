<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Enums;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The settings of a SAML 2.0 connection (SSO-2.3, SSO-5.3, SSO-5.8, SSO-6.7 to
 * SSO-6.9), by the name each is stored, given, refused and reported under; the
 * value is that name. What each holds and how it is validated belongs to the
 * SAML settings; which changes need fresh authentication, and which may change
 * what existing subjects mean, is fixed here, so every part of the package
 * classifies a change the same way.
 *
 * The identity provider's trusted signing certificates are not a setting: they
 * are a set kept with the connection's keys (SSO-2.6). The service provider's
 * entity id and assertion consumer service URL are built by the endpoint
 * resolver, never stored (SSO-5.5).
 *
 * The names are stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Saml2Setting: string
{
    // The identity provider's entity id, the `Issuer` every response and
    // assertion must carry (SSO-6.4)
    case IDP_ENTITY_ID = 'idp_entity_id';

    // The identity provider's single sign-on URL the `AuthnRequest` is sent to
    case SSO_URL = 'sso_url';

    // The binding the `AuthnRequest` is sent by, HTTP-Redirect or HTTP-POST
    case SSO_BINDING = 'sso_binding';

    // Where the subject comes from: the `NameID` or an attribute (SSO-6.9)
    case SUBJECT_SOURCE = 'subject_source';

    // The attribute holding a stable identifier, when the subject comes from
    // one (SSO-6.9)
    case SUBJECT_ATTRIBUTE = 'subject_attribute';

    // The NameID format requested and accepted: `persistent`, or `email` or
    // `unspecified` by opt-in, never `transient` (SSO-6.9)
    case NAME_ID_FORMAT = 'name_id_format';

    // Whether `AuthnRequest`s are signed with the service provider's signing
    // key (SSO-5.3)
    case SIGN_AUTHN_REQUESTS = 'sign_authn_requests';

    // Whether the assertion must carry its own signature (SSO-6.2)
    case WANT_ASSERTIONS_SIGNED = 'want_assertions_signed';

    // Whether assertions must be encrypted (SSO-6.8)
    case REQUIRE_ENCRYPTED_ASSERTIONS = 'require_encrypted_assertions';

    // The signature algorithms accepted (SSO-6.7)
    case SIGNATURE_ALGORITHMS = 'signature_algorithms';

    // The key transport and data encryption algorithms accepted, AES-CBC only
    // by opt-in (SSO-6.7)
    case ENCRYPTION_ALGORITHMS = 'encryption_algorithms';

    // Whether every `AuthnRequest` asks for fresh authentication (SSO-5.3)
    case FORCE_AUTHN = 'force_authn';

    // The authentication context classes requested with `Comparison="exact"`
    // and required of the response's `AuthnContextClassRef` (SSO-5.3, SSO-6.10)
    case REQUESTED_AUTHN_CONTEXT = 'requested_authn_context';

    // The oldest the provider's `AuthnInstant` may be, in seconds; none by
    // default (SSO-6.10)
    case MAX_AUTHENTICATION_AGE_SECONDS = 'max_authentication_age_seconds';

    // Whether an unsolicited response is re-initiated (SSO-5.8)
    case IDP_INITIATED = 'idp_initiated';

    // The application start URL an unsolicited response is sent to, naming the
    // connection (SSO-5.8, D7)
    case IDP_INITIATED_START_URL = 'idp_initiated_start_url';

    // The HTTPS URL the identity provider's metadata is fetched from, for a
    // scheduled refresh (SSO-2.8)
    case METADATA_URL = 'metadata_url';

    // Whether the connection's certificates and endpoints are refreshed from
    // its metadata on a schedule (SSO-2.8)
    case METADATA_REFRESH = 'metadata_refresh';

    /**
     * The operation whose freshness a change to the setting needs, or `null`
     * when its change never widens or redirects access (SSO-2.12): what decides
     * whom the connection trusts, where it sends people, what a subject means,
     * what a signature or algorithm must be, what a response must prove of the
     * provider's authentication, and where and whether its metadata refreshes
     * is trust; the re-initiation of unsolicited responses has its own.
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
     * Whether a change to the setting may alter what existing subjects mean
     * (SSO-2.13).
     *
     * @return bool
     */
    public function altersSubject(): bool
    {
        return in_array($this, [self::IDP_ENTITY_ID, self::SUBJECT_SOURCE, self::SUBJECT_ATTRIBUTE, self::NAME_ID_FORMAT], true);
    }

    /**
     * The names of the settings a change to which may alter what existing
     * subjects mean.
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
