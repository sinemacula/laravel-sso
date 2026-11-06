<?php

declare(strict_types = 1);

/*
 * The principal change of `docs/guides/integrating-with-laravel-iam.md`
 * (SSO-8.8, SSO-12.5), as the application's principal mutation runs it, given
 * the person and the new principal's tenant (`null` for a platform principal):
 * the package's `widened()` first, in the change's own transaction on the
 * storage connection, then the application's principal guard, then the write,
 * all committing together.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Tests\Integration\Examples\Clients;

/** @var array{identity: \SineMacula\Laravel\Sso\Identities\IdentityReference, tenant: ?string} $change */
$identity = $change['identity'];
$tenantId = $change['tenant'];

$client = Clients::browser();
// @snippet-start iam-scope-widening
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;

DB::connection(StorageConnection::name())->transaction(static function () use ($identity, $tenantId, $client): void {
    app(ScopeWidening::class)->widened($identity, $tenantId, $client); // 1. the guard, suspensions, revocation

    $principals = app(Principals::class);

    $principals->guard($identity); // 2. the guard your PrincipalScope documents
    $principals->add($identity, $tenantId); // 3. the principal
});
// @snippet-end iam-scope-widening
