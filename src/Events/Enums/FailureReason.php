<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events\Enums;

/**
 * Machine-readable reason a flow or a management change was refused.
 *
 * Stable once released: a case is never renamed or reused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FailureReason: string
{
    // Unknown, disabled or incomplete connection; deliberately one answer
    case CONNECTION_UNAVAILABLE = 'connection_unavailable';

    // The application does not allow sign-in through an external provider
    case APPLICATION_NOT_ALLOWED = 'application_not_allowed';

    // No stored authorisation request, or one already consumed
    case REQUEST_UNKNOWN = 'request_unknown';

    // The request, or its verified response's bounded validity, has expired
    case REQUEST_EXPIRED = 'request_expired';

    // A signature is missing, invalid, untrusted or uses a refused algorithm
    case SIGNATURE_INVALID = 'signature_invalid';

    // The issuer is not the connection's
    case ISSUER_MISMATCH = 'issuer_mismatch';

    // The audience does not name this service provider or client
    case AUDIENCE_MISMATCH = 'audience_mismatch';

    // The recipient or destination is not the connection's ACS
    case RECIPIENT_MISMATCH = 'recipient_mismatch';

    // The assertion or ID token is outside its validity or too old
    case ASSERTION_EXPIRED = 'assertion_expired';

    // Seen before, or the single-use store could not record it
    case REPLAYED = 'replayed';

    // The ID token's nonce is not the one the request stored
    case NONCE_MISMATCH = 'nonce_mismatch';

    // The identity provider answered with an error or non-success status
    case PROVIDER_ERROR = 'provider_error';

    // Fetched metadata is past its `validUntil` or stale limit
    case METADATA_EXPIRED = 'metadata_expired';

    // An unlinked `sign_in` result the application does not allow
    case UNLINKED = 'unlinked';

    // A handoff code was presented to the redemption of another purpose
    case PURPOSE_MISMATCH = 'purpose_mismatch';

    // The verifier does not match the handoff code's challenge
    case VERIFIER_MISMATCH = 'verifier_mismatch';

    // Attempts used up for now; the result carries `retryAfter`
    case RATE_LIMITED = 'rate_limited';

    // The S256 challenge is not 43 base64url characters (RFC 7636 4.2)
    case CHALLENGE_INVALID = 'challenge_invalid';

    // A `reauthenticate` flow's session is not signed in through the connection
    case SESSION_INELIGIBLE = 'session_ineligible';

    // No connection is verified for the email's domain; answered as a match is
    case DISCOVERY_NO_MATCH = 'discovery_no_match';

    // The response or handoff code belongs to another connection
    case CONNECTION_MISMATCH = 'connection_mismatch';

    // The handoff code belongs to another application
    case APPLICATION_MISMATCH = 'application_mismatch';

    // The connection does not satisfy its tenant's enforcement
    case ENFORCEMENT_UNSATISFIED = 'enforcement_unsatisfied';

    // No handoff code is stored for what was presented, or it was voided
    case HANDOFF_UNKNOWN = 'handoff_unknown';

    // The handoff code has expired
    case HANDOFF_EXPIRED = 'handoff_expired';

    // The link resolved at completion was removed or now names another identity
    case LINK_CHANGED = 'link_changed';

    // A domain-made link is suspended until a confirming `link` flow
    case LINK_SUSPENDED = 'link_suspended';

    // The principal scope of a domain-made link could not be judged
    case PRINCIPAL_SCOPE_UNKNOWN = 'principal_scope_unknown';

    // The subject is held by another flow's live reservation
    case LINK_RESERVED = 'link_reserved';

    // The link eligibility contract refused the identity
    case LINK_INELIGIBLE = 'link_ineligible';

    // A domain-made link needs independent authentication to confirm
    case INDEPENDENT_AUTHENTICATION_REQUIRED = 'independent_authentication_required';

    // Not the identity the flow was started for
    case IDENTITY_MISMATCH = 'identity_mismatch';

    // The reservation is gone, expired or no longer holds for its identity
    case RESERVATION_INVALID = 'reservation_invalid';

    // The provisioning grant is used, closed or not for that result
    case PROVISIONING_GRANT_INVALID = 'provisioning_grant_invalid';

    // A SAML response or OIDC callback is malformed or structurally refused
    case RESPONSE_INVALID = 'response_invalid';

    // Decryption failed or used refused algorithms; deliberately one answer
    case DECRYPTION_FAILED = 'decryption_failed';

    // The connection requires encrypted assertions and got a plain one
    case ENCRYPTION_REQUIRED = 'encryption_required';

    // The response's subject is not one the connection accepts
    case SUBJECT_INVALID = 'subject_invalid';

    // `InResponseTo` or `RelayState` names another request
    case REQUEST_MISMATCH = 'request_mismatch';

    // The provider's authentication is too old, ended or has no time stated
    case AUTHENTICATION_EXPIRED = 'authentication_expired';

    // The authentication context class is not one the connection requires
    case AUTHENTICATION_CONTEXT_MISMATCH = 'authentication_context_mismatch';

    // An assertion condition the package does not understand (SAML Core 2.5.1)
    case CONDITION_UNSUPPORTED = 'condition_unsupported';

    // The connection does not allow IdP-initiated sign-in
    case UNSOLICITED_NOT_ALLOWED = 'unsolicited_not_allowed';

    // An outbound request was refused before it was sent
    case FETCH_REFUSED = 'fetch_refused';

    // An outbound request was sent and failed
    case FETCH_FAILED = 'fetch_failed';

    // The freshness contract answered `stale`; the caller must reauthenticate
    case FRESHNESS_REQUIRED = 'freshness_required';

    // No connection with that id belongs to the tenant named
    case CONNECTION_NOT_FOUND = 'connection_not_found';

    // No key or certificate with that id belongs to the connection
    case KEY_NOT_FOUND = 'key_not_found';

    // Settings were refused; the result carries the violations
    case SETTINGS_INVALID = 'settings_invalid';

    // No driver for the protocol, or its feature is off
    case PROTOCOL_UNAVAILABLE = 'protocol_unavailable';

    // The key is not in a state the operation can move it from
    case KEY_STATE_CONFLICT = 'key_state_conflict';

    // No claim of that domain belongs to the connection named
    case DOMAIN_NOT_FOUND = 'domain_not_found';

    // Verified for another connection, which is never named
    case DOMAIN_UNAVAILABLE = 'domain_unavailable';

    // The pending claim expired; claiming again gives a new token
    case DOMAIN_CLAIM_EXPIRED = 'domain_claim_expired';

    // No TXT record carries the claim's token
    case DOMAIN_RECORD_NOT_FOUND = 'domain_record_not_found';

    // The DNS resolver could not answer, which proves nothing either way
    case DOMAIN_LOOKUP_FAILED = 'domain_lookup_failed';

    // The helper's feature is off, or a refresh has nothing it may fetch
    case FEATURE_DISABLED = 'feature_disabled';

    // No satisfying connection is enabled and has completed a sign-in
    case COMPLETED_SIGN_IN_REQUIRED = 'completed_sign_in_required';

    // No link with that id belongs to the identity named
    case LINK_NOT_FOUND = 'link_not_found';

    // The identity is at the link limit for the connection
    case LINK_LIMIT_REACHED = 'link_limit_reached';

    // The issuer and subject are already linked in the connection
    case SUBJECT_ALREADY_LINKED = 'subject_already_linked';

    // A subject-changing setting was refused because the connection has links
    case CONNECTION_HAS_LINKS = 'connection_has_links';

    // A subject migration did not account for every link exactly once
    case LINKS_UNACCOUNTED = 'links_unaccounted';

    // Identity provider metadata is malformed or unusable
    case METADATA_INVALID = 'metadata_invalid';

    // Metadata is unsigned under an anchor, or its signature does not verify
    case METADATA_SIGNATURE_INVALID = 'metadata_signature_invalid';

    // Not exactly one entity with the pinned entity id
    case METADATA_ENTITY_NOT_FOUND = 'metadata_entity_not_found';

    // A refresh lost to a concurrent change and wrote nothing
    case METADATA_CONFLICT = 'metadata_conflict';

    // Another server holds the connection's refresh claim
    case METADATA_REFRESH_IN_PROGRESS = 'metadata_refresh_in_progress';

    // The ID token is missing, malformed or has a claim of the wrong type
    case ID_TOKEN_INVALID = 'id_token_invalid';

    // The token response is not one JSON object with a `Bearer` access token
    case TOKEN_RESPONSE_INVALID = 'token_response_invalid';

    // `at_hash` does not match the access token (OIDC Core 3.1.3.8)
    case AT_HASH_MISMATCH = 'at_hash_mismatch';

    // The UserInfo response is malformed or its `sub` is not the ID token's
    case USERINFO_INVALID = 'userinfo_invalid';

    // The discovery document is malformed or unusable
    case DISCOVERY_INVALID = 'discovery_invalid';

    // The JWKS is malformed, too large, ambiguous or has no usable key
    case JWKS_INVALID = 'jwks_invalid';
}
