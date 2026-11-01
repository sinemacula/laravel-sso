<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * One connection, as a protocol driver and the package's helpers read it
 * (SSO-2.1): its id, its tenant and protocol (both fixed at creation), its
 * display name, its settings, its attribute mapping, whether it is enabled, and
 * whether a sign-in through it has ever been completed (SSO-4.3).
 *
 * It never exposes a secret: a client secret or a private key is decrypted only
 * by the code that must use it, through `Contracts\SecretEncrypter`, and the
 * settings it answers hold none (SSO-2.5). The package's model,
 * `Models\Connection`, implements it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SsoConnection
{
    /**
     * The connection's id: an opaque string, the `{connection}` of its
     * endpoints.
     *
     * @return string
     */
    public function getConnectionId(): string;

    /**
     * The opaque id of the tenant the connection belongs to.
     *
     * @return string
     */
    public function getTenantId(): string;

    /**
     * The name of the driver the connection runs over: `saml2`, `oidc` or one
     * an application registered.
     *
     * @return string
     */
    public function getProtocol(): string;

    /**
     * The name administrators know the connection by.
     *
     * @return string
     */
    public function getDisplayName(): string;

    /**
     * The settings as stored, by name, with no secret among them.
     *
     * @return array<string, mixed>
     */
    public function getSettings(): array;

    /**
     * The attribute mapping as stored: each target attribute of the result, by
     * the SAML attribute or OIDC claim it is read from (SSO-2.10).
     *
     * @return array<string, mixed>
     */
    public function getAttributeMapping(): array;

    /**
     * Whether the connection is enabled. A connection is used only while it is
     * enabled and its settings are complete (SSO-2.1).
     *
     * @return bool
     */
    public function isEnabled(): bool;

    /**
     * Whether a `sign_in` through the connection has ever been redeemed, which
     * enforcement needs before it can be turned on (SSO-4.3).
     *
     * @return bool
     */
    public function hasCompletedSignIn(): bool;
}
