<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Events\Enums;

/**
 * Machine-readable reason a flow was refused (SSO-10.2): an authorisation
 * request, a SAML response at the assertion consumer service, an OIDC callback
 * or a handoff redemption. It is carried on the one failure event each refused
 * operation fires, on the result an operation returns, and as the code a
 * failure redirect carries (SSO-5.7); the application words it (SSO-12.6).
 *
 * The administration group is the reason a management helper refused a change
 * (SSO-2.11, SSO-2.12), carried on the helper's result only: a refused change
 * fires no event, since it changed nothing.
 *
 * Backed, so SIEM consumers count failure modes without scraping log messages,
 * and stable once released: a case is never renamed or reused, and a removed
 * one leaves its value unused. Each later item adds the cases it reports here,
 * in the group of its flow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FailureReason: string
{
    // The connection is unknown, disabled or its settings are incomplete; the
    // same answer for each, so a refusal says nothing of which (SSO-2.1,
    // SSO-3.5)
    case CONNECTION_UNAVAILABLE = 'connection_unavailable';

    // The application does not allow sign-in through an external provider
    // (SSO-5.1, SSO-9.2)
    case APPLICATION_NOT_ALLOWED = 'application_not_allowed';

    // The response or callback names no stored authorisation request, or one
    // already consumed (SSO-5.1, SSO-6.6, SSO-7.1)
    case REQUEST_UNKNOWN = 'request_unknown';

    // The authorisation request has expired
    case REQUEST_EXPIRED = 'request_expired';

    // A signature is missing where one is required, does not verify, is not
    // from a trusted certificate or key, or uses an algorithm the connection
    // does not allow (SSO-6.2, SSO-6.7, SSO-7.3)
    case SIGNATURE_INVALID = 'signature_invalid';

    // The issuer of the response, assertion, ID token or authorisation response
    // is not the connection's (SSO-6.4, SSO-7.1, SSO-7.4)
    case ISSUER_MISMATCH = 'issuer_mismatch';

    // An audience restriction or the ID token's audience does not name this
    // service provider or client (SSO-6.4, SSO-7.4)
    case AUDIENCE_MISMATCH = 'audience_mismatch';

    // The bearer confirmation's recipient or the response's destination is not
    // the connection's assertion consumer service (SSO-6.4)
    case RECIPIENT_MISMATCH = 'recipient_mismatch';

    // The assertion or ID token is not yet valid, has expired or is older than
    // the maximum age allowed (SSO-6.5, SSO-7.4)
    case ASSERTION_EXPIRED = 'assertion_expired';

    // The assertion id was seen before, the handoff code was already redeemed,
    // or the single-use store could not record either (SSO-6.6, SSO-9.2,
    // SSO-11.5)
    case REPLAYED = 'replayed';

    // The ID token's nonce is not the one the request stored (SSO-7.4)
    case NONCE_MISMATCH = 'nonce_mismatch';

    // The identity provider answered with an error or a status other than
    // success (SSO-6.9, SSO-7.1)
    case PROVIDER_ERROR = 'provider_error';

    // The connection's settings came from metadata whose `validUntil` has
    // passed, and no refresh has succeeded since (SSO-2.8)
    case METADATA_EXPIRED = 'metadata_expired';

    // A `sign_in` result resolves to no identity, holds no reservation, and the
    // application does not allow unlinked handoffs (SSO-8.6)
    case UNLINKED = 'unlinked';

    // A handoff code was presented to the redemption of another purpose
    // (SSO-9.9)
    case PURPOSE_MISMATCH = 'purpose_mismatch';

    // The verifier presented with a handoff code does not match the challenge
    // the code is bound to (SSO-5.2, SSO-9.2)
    case VERIFIER_MISMATCH = 'verifier_mismatch';

    // The IP address, email domain or connection has used up its attempts for
    // now; the result carries `retryAfter` (SSO-11.8)
    case RATE_LIMITED = 'rate_limited';

    // The S256 challenge a start was given is not 43 base64url characters (RFC
    // 7636 §4.2, SSO-5.1)
    case CHALLENGE_INVALID = 'challenge_invalid';

    // A `reauthenticate` flow names an identity and a session the
    // reauthentication contract does not find signed in through the connection
    // (SSO-5.10)
    case SESSION_INELIGIBLE = 'session_ineligible';

    // Discovery found no enabled connection the email's domain is verified
    // for; the client is answered with the application's fallback, exactly as
    // a match is answered (SSO-3.4, SSO-3.5)
    case DISCOVERY_NO_MATCH = 'discovery_no_match';

    // A response arrived at another connection's endpoint than the one its
    // authorisation request names, or a handoff code was redeemed for another
    // connection than the one it is bound to (SSO-5.5, SSO-9.2)
    case CONNECTION_MISMATCH = 'connection_mismatch';

    // A handoff code was redeemed for another application than the one it is
    // bound to (SSO-9.2)
    case APPLICATION_MISMATCH = 'application_mismatch';

    // The connection does not satisfy its tenant's enforcement for the
    // application, at completion or at redemption (SSO-4.1, SSO-4.6)
    case ENFORCEMENT_UNSATISFIED = 'enforcement_unsatisfied';

    // No handoff code is stored for what was presented, or it was voided
    // (SSO-9.2, SSO-2.13)
    case HANDOFF_UNKNOWN = 'handoff_unknown';

    // The handoff code has expired (SSO-9.2)
    case HANDOFF_EXPIRED = 'handoff_expired';

    // The link a handoff code resolved at completion was removed, or now names
    // another identity (SSO-8.5, SSO-9.9)
    case LINK_CHANGED = 'link_changed';

    // An outbound request was refused before it was sent: not `https`, an
    // address in a refused range, a redirect where none may be followed, or a
    // redirect to a refused address (SSO-2.9)
    case FETCH_REFUSED = 'fetch_refused';

    // An outbound request was sent and failed: the host did not resolve, the
    // connection or the TLS handshake failed, the response was too large or too
    // slow, or it redirected too often (SSO-2.9)
    case FETCH_FAILED = 'fetch_failed';

    // The freshness contract answered `stale`, so the caller must authenticate
    // again within the operation's maximum age: a management helper's refusal
    // (SSO-2.11, SSO-2.12), and a `link` flow's start, which reports it once as
    // any refused start does (SSO-5.11)
    case FRESHNESS_REQUIRED = 'freshness_required';

    // No connection with that id belongs to the tenant named
    case CONNECTION_NOT_FOUND = 'connection_not_found';

    // No key or certificate with that id belongs to the connection
    case KEY_NOT_FOUND = 'key_not_found';

    // A setting, the attribute mapping or a certificate was refused; the result
    // carries the violations
    case SETTINGS_INVALID = 'settings_invalid';

    // No driver is registered under the protocol, or its feature is off in
    // `sso.features`
    case PROTOCOL_UNAVAILABLE = 'protocol_unavailable';

    // The key is not in a state the operation can move it from: making current
    // a key that is not next, retiring the current key, adding a second next
    // key
    case KEY_STATE_CONFLICT = 'key_state_conflict';

    // No claim of that domain belongs to the connection named
    case DOMAIN_NOT_FOUND = 'domain_not_found';

    // The domain is verified for another connection, of this tenant or any
    // other; which one is never said (SSO-3.2)
    case DOMAIN_UNAVAILABLE = 'domain_unavailable';

    // The pending claim expired before it was verified; claiming the domain
    // again gives it a new token (SSO-3.2)
    case DOMAIN_CLAIM_EXPIRED = 'domain_claim_expired';

    // The domain's TXT record is missing, or none of its records is the claim's
    // token (SSO-3.2)
    case DOMAIN_RECORD_NOT_FOUND = 'domain_record_not_found';

    // The DNS resolver could not answer, which proves nothing either way; the
    // verification can be tried again (SSO-3.2, decision D3)
    case DOMAIN_LOOKUP_FAILED = 'domain_lookup_failed';

    // The feature the helper belongs to is off in `sso.features`
    case FEATURE_DISABLED = 'feature_disabled';

    // Enforcement cannot be turned on: none of the connections that would
    // satisfy it is enabled and has completed a sign-in (SSO-4.3)
    case COMPLETED_SIGN_IN_REQUIRED = 'completed_sign_in_required';

    // No link with that id belongs to the identity named (SSO-8.4)
    case LINK_NOT_FOUND = 'link_not_found';

    // The identity holds as many links in the connection as the link limit
    // contract allows (SSO-8.4)
    case LINK_LIMIT_REACHED = 'link_limit_reached';

    // The issuer and subject are already linked in the connection, to this
    // identity or another (SSO-8.4, SSO-5.11)
    case SUBJECT_ALREADY_LINKED = 'subject_already_linked';

    // A change that may alter the meaning of the connection's subjects was
    // refused because the connection has links; the migration helper relinks or
    // removes them first (SSO-2.13)
    case CONNECTION_HAS_LINKS = 'connection_has_links';
}
