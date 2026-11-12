<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

/**
 * One connection as a protocol driver and the package's helpers read it.
 *
 * Never expose a secret; settings answered here hold none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SsoConnection
{
    /**
     * An opaque id, the `{connection}` of its endpoints.
     *
     * @return string
     */
    public function getConnectionId(): string;

    /**
     * The opaque tenant id, fixed at creation.
     *
     * @return string
     */
    public function getTenantId(): string;

    /**
     * The driver name, fixed at creation: `saml2`, `oidc` or a registered one.
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
     * The settings as stored, with no secret.
     *
     * @return array<string, mixed>
     */
    public function getSettings(): array;

    /**
     * Each result attribute, keyed by the SAML attribute or OIDC claim it is
     * read from.
     *
     * @return array<string, mixed>
     */
    public function getAttributeMapping(): array;

    /**
     * Whether the connection is enabled; it is used only when also complete.
     *
     * @return bool
     */
    public function isEnabled(): bool;

    /**
     * Whether a `sign_in` through it was ever redeemed; enforcement needs one.
     *
     * @return bool
     */
    public function hasCompletedSignIn(): bool;

    /**
     * The settings for linking by a verified domain, kept apart from the
     * protocol settings.
     *
     * @return array<string, bool|int|string|null>
     */
    public function getLinkingSettings(): array;

    /**
     * The authentication context values accepted as evidence, empty for none.
     *
     * @return array<string, mixed>
     */
    public function getEvidencePolicy(): array;
}
