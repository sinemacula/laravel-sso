<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Linking contract (SSO-8.2, SSO-8.3, AUTH-3.9): what a verified result's link
 * resolves to, through a link keyed by its connection, its issuer and its
 * subject (for SAML, the `NameID` with its format): linked, absent, reserved or
 * suspended (`Links\LinkResolution`). Only `absent` lets a result be
 * provisioned, reserve a link or take an unlinked handoff.
 *
 * A result matches a link only through the connection it completed through, so
 * a tenant administrator who enters another identity provider's issuer in their
 * own connection reaches none of that provider's links. Nothing else in the
 * result (a name, an email, any mapped attribute) ever selects an identity. A
 * reservation resolves nothing, and neither does a link whose verified domain
 * provenance is suspended (SSO-8.8); neither is an unlinked subject.
 *
 * The default, `Links\NoLinks`, links nothing. The package's link store,
 * `Links\LinkStore`, implements it over the links table; the application or
 * `laravel-iam` binds it, and under `laravel-iam` the same store answers
 * `laravel-authentication`'s link contract, so both packages see the same
 * links. An implementation reads from the write connection (SSO-11.3), keeps
 * nothing of one call for the next (SSO-11.2), and lets a database error
 * propagate; it never answers an identity it cannot vouch for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Linker
{
    /**
     * What the result's connection, issuer and subject resolve to.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     */
    public function resolve(VerifiedResult $result): LinkResolution;
}
