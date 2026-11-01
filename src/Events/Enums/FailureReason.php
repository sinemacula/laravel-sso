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

    // The assertion id was seen before, or the single-use store could not
    // record it (SSO-6.6, SSO-11.5)
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

    // An outbound request was refused before it was sent: not `https`, an
    // address in a refused range, a redirect where none may be followed, or a
    // redirect to a refused address (SSO-2.9)
    case FETCH_REFUSED = 'fetch_refused';

    // An outbound request was sent and failed: the host did not resolve, the
    // connection or the TLS handshake failed, the response was too large or too
    // slow, or it redirected too often (SSO-2.9)
    case FETCH_FAILED = 'fetch_failed';

    // Administration, on a management helper's result only: the freshness
    // contract answered `stale`, so the caller must authenticate again within
    // the operation's maximum age (SSO-2.11, SSO-2.12)
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
}
