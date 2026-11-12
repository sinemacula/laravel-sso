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
 * The lock on an identity's linking changes, the first lock of the package's
 * order.
 *
 * Several identities are locked in ascending `digest()` order. A guard row is
 * never deleted, since another transaction may be waiting on it.
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
     * The digest of the identity's type and id, length-prefixed so no two pairs
     * collide.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return string
     */
    public static function digest(IdentityReference $identity): string
    {
        return hash('sha256', self::DIGEST_VERSION . "\0" . strlen($identity->type) . "\0" . $identity->type . "\0" . $identity->id);
    }

    /**
     * Lock the identity's guard by an upsert until the caller's transaction
     * ends; it is a current read, never a stale snapshot.
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
     * Record on the held guard that the identity has held a domain-made link;
     * never cleared.
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
     * Whether the identity has ever held a domain-made link, by a locking read
     * of the held guard.
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
