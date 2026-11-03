<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's principals (SSO-8.8), in its own `principals` table
 * on the package's storage connection, so a principal commits with the widening
 * reported before it: each a person's membership of a tenant, or a platform
 * principal when it names no tenant.
 *
 * Every writer of a person's principals takes the person's guard first, a row
 * of the application's `principal_guards` table locked until the commit, which
 * is the guard its `PrincipalScope` documents: locking the person's principals
 * alone would not hold back one being added.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Principals
{
    /** @var string The application's table of principals. */
    public const string TABLE = 'principals';

    /** @var string The application's table of each person's principal guard. */
    public const string GUARDS = 'principal_guards';

    /**
     * Take the person's principal guard, held until the transaction ends,
     * inserting it when the person has none yet.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     */
    public function guard(IdentityReference $identity): void
    {
        $guard = ['identity_type' => $identity->type, 'identity_id' => $identity->id];

        self::table(self::GUARDS)->insertOrIgnore($guard);
        self::table(self::GUARDS)->where($guard)->lockForUpdate()->first();
    }

    /**
     * Give the person a principal of the tenant, `null` for a platform
     * principal.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $tenantId
     * @return void
     */
    public function add(IdentityReference $identity, ?string $tenantId): void
    {
        self::table(self::TABLE)->insert(['identity_type' => $identity->type, 'identity_id' => $identity->id, 'tenant_id' => $tenantId]);
    }

    /**
     * The tenant of each of the person's principals, in the order given, `null`
     * for a platform principal.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return list<?string>
     */
    public function tenantsOf(IdentityReference $identity): array
    {
        $tenants = self::table(self::TABLE)->where('identity_type', $identity->type)->where('identity_id', $identity->id)->orderBy('id')->pluck('tenant_id')->all();

        return array_values(array_map(static fn (mixed $tenant): ?string => is_string($tenant) ? $tenant : null, $tenants));
    }

    /**
     * A query of the application's table, on the package's storage connection.
     *
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    private static function table(string $table): Builder
    {
        return DB::connection(StorageConnection::name())->table($table);
    }
}
