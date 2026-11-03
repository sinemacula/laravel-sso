<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Standalone;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Evidence\AcceptedEvidence;
use SineMacula\Laravel\Sso\Flows\Enums\SessionStanding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * An application's sessions: a table on the package's storage connection and
 * the two contracts that read and change it. A revocation deletes what its
 * scope no longer allows through that same Laravel connection, so it commits or
 * rolls back with the change whose transaction the package has open. A test
 * sets `failure` to have it throw once it has written, which rolls that change
 * back.
 *
 * Every value it stores is a string it wrote itself, so it reads back the same
 * on every engine.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationRevocation implements ReauthenticationSessions, SessionRevocation
{
    /** @var string The sessions table. */
    public const string TABLE = 'standalone_sessions';

    /** @var string The form an authentication time is kept in. */
    private const string TIME_FORMAT = 'Y-m-d\TH:i:s\Z';

    /** @var ?\Throwable What it throws once it has revoked. */
    public ?\Throwable $failure = null;

    /** @var list<\SineMacula\Laravel\Sso\Revocation\RevocationScope> Each scope it was asked to revoke, in order. */
    public array $scopes = [];

    /** @var list<int> The storage connection's transaction level at each revocation. */
    public array $levels = [];

    /** @var list<?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence> The evidence given with each renewal, in order. */
    public array $renewals = [];

    /**
     * Create the sessions table on the storage connection.
     *
     * @return void
     */
    public static function create(): void
    {
        Schema::connection(StorageConnection::name())->create(self::TABLE, static function (Blueprint $table): void {
            $table->string('id', 64)->primary();
            $table->string('tenant_id');
            $table->string('application');
            $table->char('connection_id', 26);
            $table->string('link_id')->nullable();
            $table->string('identity_type');
            $table->string('identity_id');
            $table->string('authenticated_at', 32);
        });
    }

    /**
     * Drop the sessions table.
     *
     * @return void
     */
    public static function drop(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(self::TABLE);
    }

    /**
     * Write a session, in whatever transaction the storage connection has open,
     * as a redeemer does once a redemption answers `redeemed`.
     *
     * @param  string  $sessionId
     * @param  string  $tenantId
     * @param  string  $application
     * @param  string  $connectionId
     * @param  ?string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @return void
     */
    public static function establish(
        string $sessionId,
        string $tenantId,
        string $application,
        string $connectionId,
        ?string $linkId,
        IdentityReference $identity,
        CarbonImmutable $authenticatedAt,
    ): void {
        self::sessions()->insert([
            'id'               => $sessionId,
            'tenant_id'        => $tenantId,
            'application'      => $application,
            'connection_id'    => $connectionId,
            'link_id'          => $linkId,
            'identity_type'    => $identity->type,
            'identity_id'      => $identity->id,
            'authenticated_at' => self::stamp($authenticatedAt),
        ]);
    }

    /**
     * The id of every session, in order.
     *
     * @return list<string>
     */
    public static function sessionIds(): array
    {
        /** @var list<string> */
        return self::sessions()->orderBy('id')->pluck('id')->all();
    }

    /**
     * When the session last authenticated, as it is kept.
     *
     * @param  string  $sessionId
     * @return ?string
     */
    public static function authenticatedAt(string $sessionId): ?string
    {
        $time = self::sessions()->where('id', $sessionId)->value('authenticated_at');

        return is_string($time) ? $time : null;
    }

    /**
     * Delete what the scope no longer allows, on the transaction the storage
     * connection has open, then throw the failure set.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function revoke(RevocationScope $scope): void
    {
        $this->scopes[] = $scope;
        $this->levels[] = DB::connection(StorageConnection::name())->transactionLevel();

        $sessions = self::sessions()->where('tenant_id', $scope->tenantId);

        match ($scope->kind) {
            RevocationScopeKind::TENANT              => $sessions->whereNotIn('connection_id', $scope->policy->connectionIds ?? [])->delete(),
            RevocationScopeKind::CONNECTION          => $sessions->where('connection_id', $scope->connectionId)->delete(),
            RevocationScopeKind::IDENTITY_CONNECTION => self::ofIdentity($sessions->where('connection_id', $scope->connectionId), $scope->identity)->delete(),
            RevocationScopeKind::IDENTITY_LINK       => $sessions->where('link_id', $scope->linkId)->delete(),
        };

        if ($this->failure !== null) {
            throw $this->failure;
        }
    }

    /**
     * Whether the identity is signed in through the connection on the session.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    #[\Override]
    public function standing(IdentityReference $identity, string $sessionId, SsoConnection $connection): SessionStanding
    {
        $session = self::ofIdentity(self::sessions(), $identity)->where('id', $sessionId)->where('connection_id', $connection->getConnectionId())->first();

        return $session === null ? SessionStanding::NOT_SIGNED_IN : SessionStanding::SIGNED_IN;
    }

    /**
     * Whether the identity is signed in on the session, of the application and
     * the connection, through exactly the link, with the session's row locked
     * until the redemption's transaction ends.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  string  $linkId
     * @return \SineMacula\Laravel\Sso\Flows\Enums\SessionStanding
     */
    #[\Override]
    public function lockedStanding(IdentityReference $identity, string $sessionId, string $application, SsoConnection $connection, string $linkId): SessionStanding
    {
        $session = self::ofIdentity(self::sessions(), $identity)
            ->useWritePdo()
            ->lockForUpdate()
            ->where('id', $sessionId)
            ->where('application', $application)
            ->where('connection_id', $connection->getConnectionId())
            ->where('link_id', $linkId)
            ->first();

        return $session === null ? SessionStanding::NOT_SIGNED_IN : SessionStanding::SIGNED_IN;
    }

    /**
     * Renew the session's authentication time, and nothing else about it.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $sessionId
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Sso\Evidence\AcceptedEvidence  $evidence
     * @return void
     */
    #[\Override]
    public function renewAuthentication(IdentityReference $identity, string $sessionId, CarbonImmutable $authenticatedAt, ?AcceptedEvidence $evidence): void
    {
        $this->renewals[] = $evidence;

        self::ofIdentity(self::sessions(), $identity)->where('id', $sessionId)->update(['authenticated_at' => self::stamp($authenticatedAt)]);
    }

    /**
     * The sessions table, on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function sessions(): Builder
    {
        return DB::connection(StorageConnection::name())->table(self::TABLE);
    }

    /**
     * The query, of the identity's sessions.
     *
     * @param  \Illuminate\Database\Query\Builder  $sessions
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \Illuminate\Database\Query\Builder
     */
    private static function ofIdentity(Builder $sessions, ?IdentityReference $identity): Builder
    {
        return $sessions->where('identity_type', $identity?->type)->where('identity_id', $identity?->id);
    }

    /**
     * The instant, as it is kept.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     * @return string
     */
    private static function stamp(CarbonImmutable $instant): string
    {
        return $instant->utc()->format(self::TIME_FORMAT);
    }
}
