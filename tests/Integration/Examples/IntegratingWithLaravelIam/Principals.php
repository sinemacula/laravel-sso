<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's principals, on the package's storage connection.
 * Writers lock the person's guard row first: locking principals misses inserts.
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
     * Lock the person's principal guard until the transaction ends.
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
     * The tenant of each of the person's principals, `null` for a platform one.
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
