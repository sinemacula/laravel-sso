<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;

/**
 * How a refresh of one connection's metadata ended (SSO-2.8, SSO-11.12): its
 * outcome, the connection, and what goes with the outcome.
 *
 * - `refreshed`: the names of the settings it changed, in the order the
 *   connection's settings name them, then `idp_signing_certificates` when the
 *   trusted certificates changed (none when nothing did); the connection's
 *   metadata version after it; and whether it changed the connection's trust,
 *   voiding the flows in flight through it.
 * - `failed`: the reason, how many refreshes have failed in a row, and when the
 *   next is due.
 * - `rate_limited` (`rate_limited`): an administrator's refresh past the
 *   connection's metadata limit, with the seconds until the window ends.
 * - `conflict` (`metadata_conflict`), `in_progress`
 *   (`metadata_refresh_in_progress`), `skipped`, and `refused`
 *   (`connection_not_found`, `feature_disabled` or `freshness_required`), with
 *   nothing else.
 *
 * It holds no certificate, URL or other value of the metadata.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefreshResult implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome  $outcome
     * @param  ?string  $connectionId
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  list<string>  $changedSettings
     * @param  ?int  $metadataVersion
     * @param  bool  $trustChanged
     * @param  ?int  $failures
     * @param  ?\Carbon\CarbonImmutable  $nextAttemptAt
     * @param  ?int  $retryAfter
     *
     * @SuppressWarnings("php:S107")
     */
    private function __construct(

        /** How the refresh ended. */
        public RefreshOutcome $outcome,

        /** The connection refreshed, or `null` when none was found. */
        public ?string $connectionId,

        /** Why it did not refresh, for every outcome but `refreshed` and `skipped`. */
        public ?FailureReason $reason = null,

        /** The names of the settings a refresh changed, in order, each once. */
        public array $changedSettings = [],

        /** The connection's metadata version after a refresh. */
        public ?int $metadataVersion = null,

        /** Whether a refresh changed the connection's trust. */
        public bool $trustChanged = false,

        /** How many refreshes have failed in a row, for a failed one. */
        public ?int $failures = null,

        /** When the next refresh is due, in UTC, for a failed one. */
        public ?CarbonImmutable $nextAttemptAt = null,

        /** The seconds until another refresh may be asked for, for a rate limited one. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * The metadata was applied.
     *
     * @param  string  $connectionId
     * @param  list<string>  $changedSettings
     * @param  int  $metadataVersion
     * @param  bool  $trustChanged
     * @return self
     */
    public static function refreshed(string $connectionId, array $changedSettings, int $metadataVersion, bool $trustChanged): self
    {
        return new self(RefreshOutcome::REFRESHED, $connectionId, changedSettings: $changedSettings, metadataVersion: $metadataVersion, trustChanged: $trustChanged);
    }

    /**
     * The refresh failed for the reason; the next is due at the instant.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  int  $failures
     * @param  \Carbon\CarbonImmutable  $nextAttemptAt
     * @return self
     */
    public static function failed(string $connectionId, FailureReason $reason, int $failures, CarbonImmutable $nextAttemptAt): self
    {
        return new self(RefreshOutcome::FAILED, $connectionId, $reason, failures: $failures, nextAttemptAt: $nextAttemptAt);
    }

    /**
     * The connection changed while its metadata was fetched; nothing was
     * written.
     *
     * @param  string  $connectionId
     * @return self
     */
    public static function conflict(string $connectionId): self
    {
        return new self(RefreshOutcome::CONFLICT, $connectionId, FailureReason::METADATA_CONFLICT);
    }

    /**
     * An administrator's refresh past the connection's metadata limit, which
     * ran nothing.
     *
     * @param  string  $connectionId
     * @param  int  $retryAfter
     * @return self
     */
    public static function rateLimited(string $connectionId, int $retryAfter): self
    {
        return new self(RefreshOutcome::RATE_LIMITED, $connectionId, FailureReason::RATE_LIMITED, retryAfter: $retryAfter);
    }

    /**
     * Another server holds the connection's refresh claim.
     *
     * @param  string  $connectionId
     * @return self
     */
    public static function inProgress(string $connectionId): self
    {
        return new self(RefreshOutcome::IN_PROGRESS, $connectionId, FailureReason::METADATA_REFRESH_IN_PROGRESS);
    }

    /**
     * Another server claimed or refreshed the connection since it was listed.
     *
     * @param  string  $connectionId
     * @return self
     */
    public static function skipped(string $connectionId): self
    {
        return new self(RefreshOutcome::SKIPPED, $connectionId);
    }

    /**
     * The refresh was refused for the reason before anything ran.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?string  $connectionId
     * @return self
     */
    public static function refused(FailureReason $reason, ?string $connectionId = null): self
    {
        return new self(RefreshOutcome::REFUSED, $connectionId, $reason);
    }

    /**
     * Whether the metadata was applied.
     *
     * @return bool
     */
    public function isRefreshed(): bool
    {
        return $this->outcome === RefreshOutcome::REFRESHED;
    }

    /**
     * The result as data, with snake_case keys and the time in UTC.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'outcome'          => $this->outcome->value,
            'connection_id'    => $this->connectionId,
            'reason'           => $this->reason?->value,
            'changed_settings' => $this->changedSettings,
            'metadata_version' => $this->metadataVersion,
            'trust_changed'    => $this->trustChanged,
            'failures'         => $this->failures,
            'next_attempt_at'  => $this->nextAttemptAt?->utc()->toIso8601String(),
            'retry_after'      => $this->retryAfter,
        ];
    }
}
