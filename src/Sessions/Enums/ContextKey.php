<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Sessions\Enums;

/**
 * A key the package contributes to the authentication context.
 *
 * Values are stable from 1.0.0; never rename or reuse one.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ContextKey: string
{
    // The connection's opaque id
    case CONNECTION = 'sso.connection';

    // The connection's tenant at sign-in, not the active tenant
    case TENANT = 'sso.tenant';

    // The registered driver's name
    case PROTOCOL = 'sso.protocol';

    // When the provider authenticated the person
    case PROVIDER_AUTH_TIME = 'sso.provider_auth_time';

    // The accepted RFC 8176 methods
    case PROVIDER_AMR = 'sso.provider_amr';

    // The accepted raw `acr`, of any driver but `saml2`
    case PROVIDER_ACR = 'sso.provider_acr';

    // The accepted raw SAML `AuthnContextClassRef`
    case PROVIDER_AUTHN_CONTEXT_CLASS_REF = 'sso.provider_authn_context_class_ref';

    // The exact link admitted
    case LINK = 'sso.link';

    // The admitted link's provenance
    case LINK_PROVENANCE = 'sso.link_provenance';

    // The provider's raw session deadline
    case PROVIDER_SESSION_DEADLINE = 'sso.provider_session_deadline';

    // The effective cap on the application's session
    case SESSION_NOT_AFTER = 'sso.session_not_after';

    // The enforcement version the sign-in's redemption judged
    case ENFORCEMENT_VERSION = 'sso.enforcement_version';

    /**
     * The type of the key's value when it is not `null`.
     *
     * @return \SineMacula\Laravel\Sso\Sessions\Enums\ContextValueType
     */
    public function type(): ContextValueType
    {
        return match ($this) {
            self::PROVIDER_AMR                                                                 => ContextValueType::LIST,
            self::PROVIDER_AUTH_TIME, self::PROVIDER_SESSION_DEADLINE, self::SESSION_NOT_AFTER => ContextValueType::TIME,
            default                                                                            => ContextValueType::STRING,
        };
    }
}
