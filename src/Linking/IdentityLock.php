<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\IdentityGuard;

/**
 * The lock on an identity's linking changes (SSO-8.8,
 * `docs/design/linking.md`): the first lock of the package's order, which a
 * principal widening, a reservation, an activation and a confirmation each
 * take, so no two of them for one identity ever overlap. A change to the
 * identity's principals cannot slip between what a reservation or an activation
 * judged and what it wrote, whichever connections and tenants are involved, and
 * a row that does not exist yet is protected too, since whatever would insert
 * it holds this lock first.
 *
 * `acquire()` runs one statement, on the storage connection, inside the
 * transaction the caller has open there: an insert of the identity's row unless
 * it has one, keyed by the digest of its type and id, which writes an existing
 * row. The statement locks the row exclusively until that transaction ends
 * (`ON DUPLICATE KEY UPDATE`, `ON CONFLICT ... DO UPDATE`), and racing first
 * lockers queue on it. It is a current read, so a caller's older
 * `REPEATABLE READ` snapshot never answers. On PostgreSQL under
 * `REPEATABLE READ`, a locker whose snapshot predates another locker's commit
 * fails to serialise, and the error propagates for the caller to retry its
 * whole transaction: a locker therefore never goes on from a snapshot that
 * misses what another locker did.
 *
 * A transaction holds the lock of one identity. One that changes several takes
 * them in ascending order of `digest()`, or the database aborts one of two such
 * transactions. The cost falls only on flows that touch linking: an ordinary
 * linked sign-in never takes it.
 *
 * The row also remembers that the identity has held an active link by a
 * verified domain: `recordDomainLink()` stamps `domain_linked_at` when a
 * reservation is activated, the one place such a link is made (a subject
 * migration keeps the provenance of a link that already had it), and nothing
 * ever clears it. `hasHeldDomainLink()` reads it by a locking read under the
 * lock, for `Linking\LinkConfirmationGate`: a link removed or confirmed since
 * does not make the session it established independent.
 *
 * The row names nobody, holds no subject or email, and is never deleted, since
 * another transaction may be waiting on it. Called with no transaction open on
 * the storage connection it is a `LogicException`, since the lock would end
 * with its statement; a database error propagates (SSO-11.4). It holds the
 * clock, which keeps nothing of one call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IdentityLock
{
    /** @var string The tag the identity digest's input starts with. */
    private const string DIGEST_VERSION = 'sso-identity-guard-v1';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock an inserted row is stamped from. */
        private Clock $clock,
    ) {}

    /**
     * The digest of the identity's type and id: the length of the type keeps
     * `ab` and `c` apart from `a` and `bc`, whatever the bytes.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return string
     */
    public static function digest(IdentityReference $identity): string
    {
        return hash('sha256', self::DIGEST_VERSION . "\0" . strlen($identity->type) . "\0" . $identity->type . "\0" . $identity->id);
    }

    /**
     * Lock the identity's guard until the caller's transaction ends, inserting
     * it first when the identity has none.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     *
     * @throws \LogicException
     */
    public function acquire(IdentityReference $identity): void
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() === 0) {
            throw new \LogicException('An identity is locked inside a transaction on the package\'s storage connection.');
        }

        $guard = new IdentityGuard;

        $guard->newQuery()->upsert([
            'id'            => strtolower((string) Str::ulid()),
            'identity_hash' => self::digest($identity),
            'created_at'    => UtcDateTime::format($guard, $this->clock->now()),
        ], ['identity_hash'], ['identity_hash']);
    }

    /**
     * Record, on the identity's guard its caller holds, that the identity has
     * held an active link by a verified domain, unless it is recorded already.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     */
    public function recordDomainLink(IdentityReference $identity): void
    {
        $guard = new IdentityGuard;

        $guard->newQuery()
            ->useWritePdo()
            ->where('identity_hash', self::digest($identity))
            ->whereNull('domain_linked_at')
            ->update(['domain_linked_at' => UtcDateTime::format($guard, $this->clock->now())]);
    }

    /**
     * Whether the identity has ever held an active link by a verified domain,
     * read by a locking read of the guard its caller holds.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    public static function hasHeldDomainLink(IdentityReference $identity): bool
    {
        return IdentityGuard::query()
            ->useWritePdo()
            ->where('identity_hash', self::digest($identity))
            ->lockForUpdate()
            ->value('domain_linked_at') !== null;
    }
}
