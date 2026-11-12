<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's users, whose row lock is the guard every writer of
 * their principals takes after the package's locks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Users
{
    /** @var string The type the application names its users by. */
    public const string TYPE = 'App\Models\User';

    /** @var string The application's table of users. */
    public const string TABLE = 'users';

    /** @var string The application's table of principals. */
    public const string PRINCIPALS = 'tenant_principals';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Lock the user's row until the transaction ends, answering whether the
     * identity is one of the application's users.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    public static function hasLockedUser(IdentityReference $identity): bool
    {
        if ($identity->type !== self::TYPE) {
            return false;
        }

        return DB::connection(StorageConnection::name())->table(self::TABLE)
            ->where('id', $identity->id)
            ->lockForUpdate()
            ->first(['id']) !== null;
    }
}
