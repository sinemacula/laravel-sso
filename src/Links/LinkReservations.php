<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\LinkLimit;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * The lifecycle of a link reservation (SSO-8.8, `docs/design/linking.md`), the
 * one place a reserved row is written. Every method runs inside a transaction
 * that holds the connection's row lock, so it is serialised with every other
 * change to the connection's links, and every creation, replacement, deletion
 * and activation raises the connection's links version, so a PostgreSQL
 * `REPEATABLE READ` transaction whose snapshot predates it fails to serialise
 * rather than miss it.
 *
 * - `reserve()`: under SSO-8.4's uniqueness and link limit, inserts the row for
 *   the matched identity with a new unique reservation identity and its
 *   binding. An expired reservation of the subject is logically absent and is
 *   replaced; any other row of the subject, the unique index included, reserves
 *   nothing.
 * - `bindHandoff()`: stores the handoff's opaque reference and its
 *   authoritative stored expiry on the row, in the transaction that issued it,
 *   so reservation and handoff expire together. An issuer that bound nothing,
 *   or stored a later expiry than it was given, is a `LogicException` that
 *   rolls the completion back: an issuer that cannot hold a reservation fails
 *   closed.
 * - `discard()`: removes the completion's own reservation when it refuses after
 *   making one.
 * - `locked()`: the row by its reservation identity alone, by a locking read.
 * - `isBoundTo()`: whether a locked row is exactly the handoff's reservation.
 * - `activate()`: makes the row active with verified domain provenance and
 *   clears every reservation field, inside the transaction that redeems its
 *   handoff.
 * - `deleteRefused()`: removes the reservation of a handoff refused after it
 *   was consumed, by its reservation identity and handoff reference and never
 *   merely by the subject, so a later reservation of that subject is untouched.
 *
 * The linking email is stored only as a digest salted with the reservation's
 * own identity. It holds the clock and the container, none of which keeps
 * anything of one flow for the next (SSO-11.2). A database error propagates
 * (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkReservations
{
    /** @var string The tag the email digest's input starts with. */
    private const string DIGEST_VERSION = 'sso-reservation-email-v1';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The clock a reservation's expiry is judged against. */
        private Clock $clock,

        /** Resolves the link limit contract at each reservation. */
        private Container $container,
    ) {}

    /**
     * The digest of the linking email under the reservation's identity.
     *
     * @param  string  $reservationId
     * @param  string  $email
     * @return string
     */
    public static function emailDigest(string $reservationId, #[\SensitiveParameter] string $email): string
    {
        return hash('sha256', self::DIGEST_VERSION . "\0" . $reservationId . "\0" . $email);
    }

    /**
     * Reserve the subject for the identity on the terms, or answer `null` when
     * the subject is held or the identity holds as many links as it may.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\ReservationTerms  $terms
     * @return ?\SineMacula\Laravel\Sso\Links\ReservedCandidate
     *
     * @throws \Throwable
     */
    public function reserve(Connection $locked, LinkSubject $subject, IdentityReference $identity, ReservationTerms $terms): ?ReservedCandidate
    {
        $this->replaceExpired($locked, $subject);

        if ($this->isFull($locked, $identity)) {
            return null;
        }

        $row           = self::reservation($locked, $subject, $identity);
        $reservationId = strtolower((string) Str::ulid());

        $row->forceFill([
            'reservation_id'                => $reservationId,
            'reservation_expires_at'        => $terms->expiresAt,
            'reservation_reference'         => $terms->reference->value,
            'reservation_email_digest'      => self::emailDigest($reservationId, $terms->email()),
            'reservation_organization'      => $terms->organization(),
            'reservation_domain_id'         => $terms->domainId,
            'reservation_domain_generation' => $terms->domainGeneration,
            'reservation_linking_version'   => $terms->linkingVersion,
        ]);

        if (!self::saved($row)) {
            return null;
        }

        self::raiseLinksVersion($locked->id);

        return new ReservedCandidate($reservationId, $identity, $row->reservation_expires_at ?? $terms->expiresAt);
    }

    /**
     * Store the handoff's reference and stored expiry on the reservation it was
     * issued for.
     *
     * @param  \SineMacula\Laravel\Sso\Links\ReservedCandidate  $candidate
     * @param  \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff  $issued
     * @return \SineMacula\Laravel\Sso\Links\ReservedCandidate
     *
     * @throws \LogicException
     */
    public function bindHandoff(ReservedCandidate $candidate, IssuedHandoff $issued): ReservedCandidate
    {
        if ($issued->reference === null || $issued->expiresAt->greaterThan($candidate->expiresAt)) {
            throw new \LogicException('A handoff issuer must store a reservation\'s binding, and never a later expiry than it was given (SSO-8.8).');
        }

        $query = Link::query()->useWritePdo();

        $query->where('reservation_id', $candidate->reservationId)->update([
            'reservation_handoff'    => $issued->reference,
            'reservation_expires_at' => UtcDateTime::format($query->getModel(), $issued->expiresAt),
        ]);

        return new ReservedCandidate($candidate->reservationId, $candidate->identity, $issued->expiresAt);
    }

    /**
     * Remove the completion's own reservation, once it refuses.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Links\ReservedCandidate  $candidate
     * @return void
     */
    public function discard(Connection $locked, ReservedCandidate $candidate): void
    {
        Link::query()->useWritePdo()
            ->where('reservation_id', $candidate->reservationId)
            ->where('state', LinkState::RESERVED->value)
            ->delete();

        self::raiseLinksVersion($locked->id);
    }

    /**
     * The reservation with the identity, by a locking read on the write
     * connection, or `null` when it is gone.
     *
     * @param  string  $reservationId
     * @return ?\SineMacula\Laravel\Sso\Models\Link
     */
    public function locked(string $reservationId): ?Link
    {
        $row = Link::query()->useWritePdo()
            ->where('reservation_id', $reservationId)
            ->where('state', LinkState::RESERVED->value)
            ->lockForUpdate()
            ->first();

        return $row?->reservation_id === $reservationId ? $row : null;
    }

    /**
     * Whether the locked row is exactly the reservation the handoff reference
     * is bound to, unexpired, in the connection, for the subject and the
     * identity.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $row
     * @param  string  $handoffReference
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isBoundTo(Link $row, string $handoffReference, string $connectionId, LinkSubject $subject): bool
    {
        $expires = $row->reservation_expires_at;

        if ($expires === null || $expires <= $this->clock->now() || $row->connection_id !== $connectionId) {
            return false;
        }

        return ConstantTime::equals((string) $row->reservation_handoff, $handoffReference)
            && (new LinkSubject($row->issuer, $row->subject, $row->name_id_format))->is($subject);
    }

    /**
     * Make the locked reservation an active link with verified domain
     * provenance, clearing every reservation field.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $row
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    public function activate(Link $row): Link
    {
        $row->forceFill([
            'state'                         => LinkState::ACTIVE,
            'provenance'                    => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'                => null,
            'reservation_expires_at'        => null,
            'reservation_reference'         => null,
            'reservation_handoff'           => null,
            'reservation_email_digest'      => null,
            'reservation_organization'      => null,
            'reservation_domain_id'         => null,
            'reservation_domain_generation' => null,
            'reservation_linking_version'   => null,
        ])->save();

        self::raiseLinksVersion($row->connection_id);

        return $row;
    }

    /**
     * Remove the reservation of a handoff refused after it was consumed, by its
     * identity and handoff reference; a row that no longer holds both is left.
     *
     * @param  string  $connectionId
     * @param  string  $reservationId
     * @param  ?string  $handoffReference
     * @return void
     */
    public function deleteRefused(string $connectionId, string $reservationId, ?string $handoffReference): void
    {
        $row = $this->locked($reservationId);

        if ($row === null || $handoffReference === null || !ConstantTime::equals((string) $row->reservation_handoff, $handoffReference)) {
            return;
        }

        $row->delete();

        self::raiseLinksVersion($connectionId);
    }

    /**
     * Delete the subject's reservation when it has expired: logically absent,
     * it holds nothing, and a later reservation takes another identity.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @return void
     */
    public function replaceExpired(Connection $locked, LinkSubject $subject): void
    {
        $row = Link::query()->useWritePdo()
            ->where('connection_id', $locked->id)
            ->where('subject_key', $subject->key())
            ->where('state', LinkState::RESERVED->value)
            ->lockForUpdate()
            ->first();

        if ($row === null || ($row->reservation_expires_at?->isAfter($this->clock->now()) ?? false)) {
            return;
        }

        $row->delete();

        self::raiseLinksVersion($locked->id);
    }

    /**
     * A reserved row of the subject for the identity, not yet saved.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private static function reservation(Connection $locked, LinkSubject $subject, IdentityReference $identity): Link
    {
        $row = new Link;

        return $row->forceFill([
            'connection_id'  => $locked->id,
            'issuer'         => $subject->issuer,
            'name_id_format' => $subject->nameIdFormat,
            'subject'        => $subject->subject,
            'subject_key'    => $subject->key(),
            'identity_type'  => $identity->type,
            'identity_id'    => $identity->id,
            'state'          => LinkState::RESERVED,
            'provenance'     => LinkOrigin::VERIFIED_DOMAIN,
        ]);
    }

    /**
     * Save the row in a savepoint, or answer `false` when the unique index on
     * the connection and the subject's key refuses it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $row
     * @return bool
     *
     * @throws \Throwable
     */
    private static function saved(Link $row): bool
    {
        try {
            DB::connection(StorageConnection::name())->transaction(static fn (): bool => $row->save());
        } catch (UniqueConstraintViolationException) {
            return false;
        }

        return true;
    }

    /**
     * Whether the identity holds as many links in the connection as it may:
     * active, suspended and live reserved ones, by a locking read.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isFull(Connection $locked, IdentityReference $identity): bool
    {
        $held = LinkHoldings::count($locked->id, $identity, $this->clock->now());

        return $held >= LinkHoldings::limitOf($this->container->make(LinkLimit::class), $identity, $locked);
    }

    /**
     * Raise the connection's links version by one.
     *
     * @param  string  $connectionId
     * @return void
     */
    private static function raiseLinksVersion(string $connectionId): void
    {
        Connection::query()->useWritePdo()->whereKey($connectionId)->increment('links_version');
    }
}
