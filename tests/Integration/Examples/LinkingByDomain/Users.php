<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's users, as its linking contracts and its principal
 * mutation read them (SSO-8.8): each user is named to the package by the
 * application's morph class and key, and their row in the application's own
 * `users` table is the guard every writer of their principals, and every writer
 * that revokes one of their memberships, takes, after the package's locks.
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
     * Take the user's guard, a locking read of their row on the package's
     * storage connection, held until the transaction ends; answer whether the
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
