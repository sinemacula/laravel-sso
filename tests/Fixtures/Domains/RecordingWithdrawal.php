<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Domains;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * A withdrawal seam that records each call: the connection, the claim, the
 * storage connection's transaction level at the time, and whether the claim's
 * row was still there, so a test proves the seam runs inside the change's
 * transaction and before its write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordingWithdrawal extends DomainWithdrawal
{
    /** @var \ArrayObject<int, array{string, string, int, bool}> Each call, in order. */
    public \ArrayObject $calls;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->calls = new \ArrayObject;
    }

    /**
     * Record the call.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return void
     */
    #[\Override]
    public function linkingWithdrawn(Connection $connection, Domain $domain): void
    {
        $level  = DB::connection(StorageConnection::name())->transactionLevel();
        $exists = Domain::query()->whereKey($domain->id)->exists();

        $this->calls->append([$connection->id, $domain->id, $level, $exists]);
    }
}
