<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Linking contract (SSO-8.2, SSO-8.3): what a verified result's link resolves
 * to, through a link keyed by its connection, its issuer and its subject (for
 * SAML, the `NameID` with its format): linked, absent, reserved, suspended or
 * of unknown scope (`Links\LinkResolution`). Only `absent` lets a result be
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
 * `Links\LinkStore`, implements it over the links table; the application or an
 * adapter binds it, and an adapter answers the link questions of the
 * application's authentication from the same store, so both see the same links.
 * Whatever writes a link needs `Contracts\LinkStorage`, which that store
 * implements and a wrapper can delegate; a `Linker` without it resolves results
 * and nothing writes through it. An implementation reads from the write
 * connection (SSO-11.3), keeps nothing of one call for the next (SSO-11.2), and
 * lets a database error propagate; it never answers an identity it cannot vouch
 * for.
 *
 * A resolution can write: the package's store latches a suspension when the
 * principal scope contract answers `outside_tenant`, and reports it with the
 * client the resolution is made for (`Http\ClientContext`), so every call takes
 * one. A caller resolving inside a transaction of its own therefore locks the
 * result's connection first, as the package's completion and redemptions do, so
 * a link is never locked before its connection (`docs/design/links.md`); one
 * with no transaction open needs nothing more.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Linker
{
    /**
     * What the result's connection, issuer and subject resolve to, for the
     * client.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     */
    public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution;
}
