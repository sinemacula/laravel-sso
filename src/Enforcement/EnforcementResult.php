<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Enforcement\Enums\EnforcementStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * How a change to a tenant's enforcement ended (SSO-4.3, SSO-4.5, SSO-2.11,
 * SSO-2.12): updated or unchanged, each with the tenant's enforcement as it now
 * is; refused, with the reason (`feature_disabled`, `freshness_required` or
 * `completed_sign_in_required`); or invalid, with every violation found and the
 * reason `settings_invalid`.
 *
 * A refusal is a value, never thrown, and changed nothing: no row was written,
 * no session revocation asked for and no event dispatched. A violation names a
 * position in the list of connection ids given and a code, never the id, so an
 * unknown id and another tenant's are refused alike.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnforcementResult implements \JsonSerializable
{
    /** @var list<\SineMacula\Laravel\Sso\Events\Enums\FailureReason> The reasons a change to an enforcement is refused for. */
    private const array REFUSALS = [
        FailureReason::FEATURE_DISABLED,
        FailureReason::FRESHNESS_REQUIRED,
        FailureReason::COMPLETED_SIGN_IN_REQUIRED,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\Enums\EnforcementStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\EnforcementSummary  $enforcement
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     */
    private function __construct(

        /** How the change ended. */
        public EnforcementStatus $status,

        /** The tenant's enforcement as it now is, for a success only. */
        public ?EnforcementSummary $enforcement = null,

        /** Why the change was refused, for `refused` and `invalid` only. */
        public ?FailureReason $reason = null,

        /** Every violation found, for `invalid` only. */
        public array $violations = [],
    ) {}

    /**
     * The tenant's enforcement was changed, with a new version.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementSummary  $enforcement
     * @return self
     */
    public static function updated(EnforcementSummary $enforcement): self
    {
        return new self(EnforcementStatus::UPDATED, $enforcement);
    }

    /**
     * The change gave what the tenant's enforcement already held; nothing was
     * written.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementSummary  $enforcement
     * @return self
     */
    public static function unchanged(EnforcementSummary $enforcement): self
    {
        return new self(EnforcementStatus::UNCHANGED, $enforcement);
    }

    /**
     * The change was refused for the reason given: `feature_disabled`,
     * `freshness_required` or `completed_sign_in_required`.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason): self
    {
        if (!in_array($reason, self::REFUSALS, true)) {
            throw new \InvalidArgumentException(sprintf('A change to an enforcement is not refused for [%s].', $reason->value));
        }

        return new self(EnforcementStatus::REFUSED, reason: $reason);
    }

    /**
     * The connection ids given were refused, for each of these violations.
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

        return new self(EnforcementStatus::INVALID, reason: FailureReason::SETTINGS_INVALID, violations: $violations);
    }

    /**
     * Whether the change succeeded: updated or unchanged.
     *
     * @return bool
     */
    public function isSucceeded(): bool
    {
        return $this->status->isSucceeded();
    }

    /**
     * Whether the change wrote something: updated.
     *
     * @return bool
     */
    public function isChanged(): bool
    {
        return $this->status === EnforcementStatus::UPDATED;
    }

    /**
     * Whether the change was refused, with a reason.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status === EnforcementStatus::REFUSED;
    }

    /**
     * Whether the connection ids given were refused, with their violations.
     *
     * @return bool
     */
    public function isInvalid(): bool
    {
        return $this->status === EnforcementStatus::INVALID;
    }

    /**
     * The result, with snake_case keys: the status, the enforcement, the reason
     * and the violations.
     *
     * @return array{status: string, enforcement: ?array<string, mixed>, reason: ?string, violations: list<array{setting: string, code: string}>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'status'      => $this->status->value,
            'enforcement' => $this->enforcement?->jsonSerialize(),
            'reason'      => $this->reason?->value,
            'violations'  => array_map(static fn (SettingViolation $violation): array => $violation->jsonSerialize(), $this->violations),
        ];
    }
}
