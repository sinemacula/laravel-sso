<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;

/**
 * The example application's link email matcher, guarded by the unique index on
 * `users.email`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UserEmailMatcher implements LinkEmailMatcher
{
    /**
     * The one user whose verified email is the query's, if any.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\LinkEmailQuery  $query
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     */
    #[\Override]
    public function match(LinkEmailQuery $query): LinkEmailMatch
    {
        $ids = DB::connection(StorageConnection::name())->table(Users::TABLE)
            ->useWritePdo()
            ->where('email', $query->email())
            ->whereNotNull('email_verified_at')
            ->limit(2)
            ->pluck('id')
            ->all();

        return match (true) {
            count($ids) > 1                      => LinkEmailMatch::ambiguous(),
            isset($ids[0]) && is_scalar($ids[0]) => LinkEmailMatch::exactlyOne(new IdentityReference(Users::TYPE, (string) $ids[0])),
            default                              => LinkEmailMatch::none(),
        };
    }
}
