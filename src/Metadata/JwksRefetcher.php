<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\JwksEvents;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits;

/**
 * Refetches a connection's JWKS on an unknown `kid` (SSO-7.3), at most once per
 * cooldown, so an identity provider can rotate its keys without a restart and a
 * flood of unknown `kid`s cannot trigger fetches.
 *
 * `refetch()` refuses to run inside a transaction on the storage connection (a
 * `LogicException`), since it fetches before it writes. From the connection as
 * read on the write connection, it:
 *
 * 1. claims the cooldown, before it fetches, with one conditional update: where
 *    the JWKS version is still the one read and `jwks_refetch_at` is unset or
 *    not after now, `jwks_refetch_at` becomes now plus
 *    `sso.oidc.jwks_refetch_cooldown_seconds` and `jwks_claim_token` a fresh
 *    random token. No row updated is `cooling_down`: no fetch, and the keys
 *    stored now are read again and answered, a winner's among them;
 * 2. fetches the `jwks_uri` read, outside any transaction, as a JWKS request
 *    held to `sso.oidc.max_jwks_bytes` (SSO-2.9), and reads it with
 *    `ProviderKeySet::read()` under the caps and the allow-list given, noting
 *    the moment it validated;
 * 3. writes, in one transaction on the storage connection whose first statement
 *    locks the connection's row, the only lock it takes.
 *
 * It compares and sets, for a success and a failure alike: the locked
 * connection must still hold its token, the JWKS version and trust version read
 * and the same `issuer` and `jwks_uri`. Otherwise it is `conflict`: it writes
 * nothing, answers the winner's keys from the locked row with no other fetch,
 * and reports `JwksRefreshFailed` with `metadata_conflict`. Then:
 *
 * - a JWKS read replaces what is stored exactly, never as a union, is
 *   `refreshed` and reports `JwksRefreshed`: `jwks_version` raised,
 *   `jwks_fetched_at` the validated moment and the token cleared, keeping
 *   `jwks_refetch_at`, so the cooldown stays. A key removed, or replaced under
 *   the same `kid`, voids what is in flight through the connection and raises
 *   its trust version once (`Connections\InFlightVoider::voidFor()`), the
 *   request whose completion asked included; a key added alone voids nothing
 *   and leaves it as it was, so a refetch never voids its own callback;
 * - a fetch refused or failed (a response not `2xx` or over the cap included)
 *   or a JWKS refused (`jwks_invalid`) is `failed`, clears the token alone,
 *   keeping the cooldown and the last good keys, and reports
 *   `JwksRefreshFailed`.
 *
 * Every event is dispatched after the transaction commits (SSO-10.5). It
 * answers how it ended for its caller to log; it logs nothing, and never holds
 * a URL, body or key in what it reports. A database error propagates
 * (SSO-11.4). It holds the limits, the fetcher, the voider, the reporter and
 * the clock, none of which keeps anything of one refetch for the next
 * (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-type JwksRefetch array{
 *     outcome: string,
 *     reason: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason,
 *     fetch_status: ?\SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus,
 *     jwks: ?string
 * }
 */
final readonly class JwksRefetcher
{
    /** @var string The refetch wrote the keys it fetched. */
    public const string REFRESHED = 'refreshed';

    /** @var string The fetch or the JWKS was refused or failed; the last good keys stand. */
    public const string FAILED = 'failed';

    /** @var string The connection changed while it fetched, and it wrote nothing. */
    public const string CONFLICT = 'conflict';

    /** @var string The cooldown holds, so nothing was fetched. */
    public const string COOLING_DOWN = 'cooling_down';

    /** @var string Why a refetch refuses to run inside a transaction. */
    private const string IN_TRANSACTION = 'A JWKS refetch runs outside any transaction on the storage connection, since it fetches before it writes.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits  $limits
     * @param  \SineMacula\Laravel\Sso\Contracts\Fetcher  $fetcher
     * @param  \SineMacula\Laravel\Sso\Connections\InFlightVoider  $voider
     * @param  \SineMacula\Laravel\Sso\Administration\JwksEvents  $events
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The cooldown and the JWKS's caps. */
        private OidcLimits $limits,

        /** Fetches the JWKS. */
        private Fetcher $fetcher,

        /** Voids what a key removed leaves in flight. */
        private InFlightVoider $voider,

        /** Reports the refetch or its failure. */
        private JwksEvents $events,

        /** The clock the cooldown and the validated moment are read from. */
        private Clock $clock,
    ) {}

    /**
     * Refetch the JWKS of the connection as read, unless the cooldown holds,
     * and answer how it ended, with the keys stored at its end.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $read
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return JwksRefetch
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function refetch(Connection $read, AlgorithmAllowList $allowed): array
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        $token = RefreshClaim::token();

        if (!$this->claimed($read, $token)) {
            return self::answer(self::COOLING_DOWN, self::stored($read));
        }

        $maxBytes = $this->limits->maxJwksBytes();
        $fetched  = $this->fetcher->fetch(FetchRequest::jwks(self::jwksUriOf($read), $maxBytes));
        $keys     = $fetched->isSuccessful() ? ProviderKeySet::read((string) $fetched->body(), $allowed, $maxBytes, $this->limits->maxJwksKeys()) : null;

        // The moment the JWKS was validated, read once the reader is done
        $validatedAt = $this->clock->now();

        return DB::connection(StorageConnection::name())->transaction(function () use ($read, $token, $fetched, $keys, $allowed, $validatedAt): array {

            $locked = Connection::query()->useWritePdo()->whereKey($read->id)->lockForUpdate()->first();

            return match (true) {
                $locked === null, !self::isUnchanged($locked, $read, $token) => $this->conflict($locked, $fetched->status),
                $keys   === null                                             => $this->failed($locked, $fetched),
                default                                                      => $this->replaced($locked, $keys, $allowed, $validatedAt),
            };
        });
    }

    /**
     * Claim the cooldown of the connection as read with the token; whether the
     * one conditional update changed its row.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $read
     * @param  string  $token
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function claimed(Connection $read, string $token): bool
    {
        $now   = $this->clock->now();
        $at    = UtcDateTime::format($read, $now);
        $until = UtcDateTime::format($read, $now->addSeconds($this->limits->jwksRefetchCooldownSeconds()));

        $claimed = Connection::query()
            ->whereKey($read->id)
            ->where('jwks_version', $read->jwks_version)
            ->where(static function (Builder $free) use ($at): void {
                $free->whereNull('jwks_refetch_at')->orWhere('jwks_refetch_at', '<=', $at);
            })
            ->update(['jwks_refetch_at' => $until, 'jwks_claim_token' => $token]);

        return $claimed === 1;
    }

    /**
     * The refetch lost to a change made while it fetched and writes nothing;
     * the failure is reported as the winner left the connection, whose keys it
     * answers.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus  $status
     * @return JwksRefetch
     *
     * @throws \InvalidArgumentException
     */
    private function conflict(?Connection $locked, FetchStatus $status): array
    {
        if ($locked !== null) {
            $this->events->refreshFailed($locked, FailureReason::METADATA_CONFLICT, $locked->jwks_refetch_at);
        }

        return self::answer(self::CONFLICT, $locked?->jwks, FailureReason::METADATA_CONFLICT, $status);
    }

    /**
     * Record a failed refetch on the locked connection: the token cleared, the
     * cooldown and the last good keys kept.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $fetched
     * @return JwksRefetch
     *
     * @throws \InvalidArgumentException
     */
    private function failed(Connection $locked, FetchResult $fetched): array
    {
        $reason = $fetched->isSuccessful() ? FailureReason::JWKS_INVALID : ($fetched->reason ?? FailureReason::FETCH_FAILED);

        $locked->forceFill(['jwks_claim_token' => null])->save();

        $this->events->refreshFailed($locked, $reason, $locked->jwks_refetch_at);

        return self::answer(self::FAILED, $locked->jwks, $reason, $fetched->status);
    }

    /**
     * Replace the locked connection's keys exactly, keeping the cooldown; a key
     * removed, or replaced under its `kid`, voids what is in flight and raises
     * the trust version once.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet  $keys
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @return JwksRefetch
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function replaced(Connection $locked, ProviderKeySet $keys, AlgorithmAllowList $allowed, CarbonImmutable $validatedAt): array
    {
        $changes = $keys->changesFrom(ProviderKeySet::fromStored($locked->jwks, $allowed));
        $removed = $changes['removed'] > 0;

        $locked->forceFill([
            'jwks'             => $keys->toStored(),
            'jwks_version'     => $locked->jwks_version + 1,
            'jwks_fetched_at'  => $validatedAt,
            'jwks_claim_token' => null,
        ])->save();

        if ($removed) {
            $this->voider->voidFor($locked);
        }

        $this->events->refreshed($locked, $changes['added'], $changes['removed'], $removed);

        return self::answer(self::REFRESHED, $locked->jwks, null, FetchStatus::FETCHED);
    }

    /**
     * How a refetch ended, with the keys stored at its end.
     *
     * @param  string  $outcome
     * @param  ?string  $jwks
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus  $status
     * @return JwksRefetch
     */
    private static function answer(string $outcome, ?string $jwks, ?FailureReason $reason = null, ?FetchStatus $status = null): array
    {
        return ['outcome' => $outcome, 'reason' => $reason, 'fetch_status' => $status, 'jwks' => $jwks];
    }

    /**
     * The keys the connection stores now, read on the write connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $read
     * @return ?string
     */
    private static function stored(Connection $read): ?string
    {
        return Connection::query()->useWritePdo()->whereKey($read->id)->first()?->jwks;
    }

    /**
     * Whether the locked connection still holds the token, the versions read
     * and the same issuer and `jwks_uri`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $read
     * @param  string  $token
     * @return bool
     */
    private static function isUnchanged(Connection $locked, Connection $read, string $token): bool
    {
        $owned    = is_string($locked->jwks_claim_token)          && hash_equals($locked->jwks_claim_token, $token);
        $versions = $locked->jwks_version === $read->jwks_version && $locked->trust_version === $read->trust_version;

        return $owned && $versions && self::pinned($locked) === self::pinned($read);
    }

    /**
     * The `jwks_uri` of the connection as read, empty when it holds none, which
     * the fetcher refuses.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return string
     */
    private static function jwksUriOf(Connection $connection): string
    {
        $uri = $connection->settings[OidcSetting::JWKS_URI->value] ?? null;

        return is_string($uri) ? $uri : '';
    }

    /**
     * The settings a refetch's keys belong to, whatever order the connection's
     * settings were read in: the issuer and the `jwks_uri`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return array{0: mixed, 1: mixed}
     */
    private static function pinned(Connection $connection): array
    {
        $settings = $connection->settings;

        return [$settings[OidcSetting::ISSUER->value] ?? null, $settings[OidcSetting::JWKS_URI->value] ?? null];
    }
}
