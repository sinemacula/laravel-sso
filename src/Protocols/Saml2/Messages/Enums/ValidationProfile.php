<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Enums;

/**
 * The validation profile a SAML message is checked by (SSO-6.11): the parsing
 * of SSO-6.1 is shared, and each kind of message has its own rules.
 *
 * - `metadata`: no assertion rules; the entity is chosen by its pinned entity
 *   id, and a signature is verified when the connection has a metadata signing
 *   anchor (SSO-2.8).
 * - `solicited`: a successful response with an `InResponseTo` somewhere:
 *   exactly one `Assertion` or `EncryptedAssertion`, and every rule of SSO-6.2
 *   to SSO-6.10.
 * - `unsuccessful`: a status other than success: no assertion is required or
 *   read, its `InResponseTo` must match a stored request, its `Issuer` must
 *   match and any signature must verify; it yields only a failure code.
 * - `unsolicited`: a successful response with no `InResponseTo` anywhere: every
 *   other rule of a successful response; it yields only re-initiation
 *   (SSO-5.8).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ValidationProfile: string
{
    // Identity provider metadata (SSO-2.8)
    case METADATA = 'metadata';

    // A successful response to an authorisation request
    case SOLICITED = 'solicited';

    // A response whose status is not success
    case UNSUCCESSFUL = 'unsuccessful';

    // A successful response to no request (SSO-5.8)
    case UNSOLICITED = 'unsolicited';
}
