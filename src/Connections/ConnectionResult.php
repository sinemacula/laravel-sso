<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a management helper's change to a connection ended (SSO-2.11, SSO-2.12):
 * created, updated, unchanged or enabled, each with the connection's summary as
 * it now is (and, when updated, the names of what changed); refused, with the
 * reason (`freshness_required`, `connection_not_found` or
 * `protocol_unavailable`); or invalid, with every violation found and the
 * reason `settings_invalid`.
 *
 * A refusal is a value, never thrown, and changed nothing: no row was written
 * and no event dispatched. A violation names a setting and a code, never the
 * value given, so the result can be returned, logged or shown whatever was
 * given, a secret included.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConnectionResult implements \JsonSerializable
{
    /** @var list<\SineMacula\Laravel\Sso\Events\Enums\FailureReason> The reasons a change to a connection is refused for. */
    private const array REFUSALS = [
        FailureReason::FRESHNESS_REQUIRED,
        FailureReason::CONNECTION_NOT_FOUND,
        FailureReason::PROTOCOL_UNAVAILABLE,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Connections\ConnectionSummary  $connection
     * @param  list<string>  $changedSettings
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     */
    private function __construct(

        /** How the change ended. */
        public ConnectionStatus $status,

        /** The connection as it now is, for a success only. */
        public ?ConnectionSummary $connection = null,

        /** The names of the settings, secrets, name or mapping that changed, for `updated` only. */
        public array $changedSettings = [],

        /** Why the change was refused, for `refused` and `invalid` only. */
        public ?FailureReason $reason = null,

        /** Every violation found, for `invalid` only. */
        public array $violations = [],
    ) {}

    /**
     * The connection was created.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSummary  $connection
     * @return self
     */
    public static function created(ConnectionSummary $connection): self
    {
        return new self(ConnectionStatus::CREATED, $connection);
    }

    /**
     * The connection was updated: these settings, secrets, its name or its
     * mapping changed, by name.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSummary  $connection
     * @param  list<string>  $changedSettings
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function updated(ConnectionSummary $connection, array $changedSettings): self
    {
        if ($changedSettings === []) {
            throw new \InvalidArgumentException('An updated connection names what changed; a change of nothing is unchanged.');
        }

        return new self(ConnectionStatus::UPDATED, $connection, $changedSettings);
    }

    /**
     * The change gave what the connection already held; nothing was written.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSummary  $connection
     * @return self
     */
    public static function unchanged(ConnectionSummary $connection): self
    {
        return new self(ConnectionStatus::UNCHANGED, $connection);
    }

    /**
     * The connection was enabled.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionSummary  $connection
     * @return self
     */
    public static function enabled(ConnectionSummary $connection): self
    {
        return new self(ConnectionStatus::ENABLED, $connection);
    }

    /**
     * The change was refused for the reason given: `freshness_required`,
     * `connection_not_found` or `protocol_unavailable`.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason): self
    {
        if (!in_array($reason, self::REFUSALS, true)) {
            throw new \InvalidArgumentException(sprintf('A change to a connection is not refused for [%s].', $reason->value));
        }

        return new self(ConnectionStatus::REFUSED, reason: $reason);
    }

    /**
     * What was given was refused, for each of these violations.
     *
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function invalid(array $violations): self
    {
        if ($violations === []) {
            throw new \InvalidArgumentException('An invalid change names at least one violation.');
        }

        return new self(ConnectionStatus::INVALID, reason: FailureReason::SETTINGS_INVALID, violations: $violations);
    }

    /**
     * Whether the change succeeded: created, updated, unchanged or enabled.
     *
     * @return bool
     */
    public function isSucceeded(): bool
    {
        return $this->isChanged() || $this->status === ConnectionStatus::UNCHANGED;
    }

    /**
     * Whether the change wrote something: created, updated or enabled.
     *
     * @return bool
     */
    public function isChanged(): bool
    {
        return in_array($this->status, [ConnectionStatus::CREATED, ConnectionStatus::UPDATED, ConnectionStatus::ENABLED], true);
    }

    /**
     * Whether the change was refused, with a reason.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status === ConnectionStatus::REFUSED;
    }

    /**
     * Whether what was given was refused, with its violations.
     *
     * @return bool
     */
    public function isInvalid(): bool
    {
        return $this->status === ConnectionStatus::INVALID;
    }

    /**
     * The result, with snake_case keys: the status, the connection, what
     * changed, the reason and the violations.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'status'           => $this->status->value,
            'connection'       => $this->connection?->jsonSerialize(),
            'changed_settings' => $this->changedSettings,
            'reason'           => $this->reason?->value,
            'violations'       => array_map(static fn (SettingViolation $violation): array => $violation->jsonSerialize(), $this->violations),
        ];
    }
}
