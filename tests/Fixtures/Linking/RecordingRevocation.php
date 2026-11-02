<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Linking;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * A session revocation that records the link each call names, and the
 * transaction level it was called at.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingRevocation implements SessionRevocation
{
    /** @var list<?string> The link each call named, in order. */
    public array $linkIds = [];

    /** @var list<int> The transaction level of each call, in order. */
    public array $levels = [];

    /**
     * Record the call.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        $this->linkIds[] = $scope->linkId;
        $this->levels[]  = DB::connection(StorageConnection::name())->transactionLevel();
    }
}
