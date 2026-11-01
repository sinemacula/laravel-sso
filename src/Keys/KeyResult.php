<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyStatus;

/**
 * What a key operation of `Keys\KeyService` did (SSO-2.6, SSO-2.7, SSO-2.11):
 * added a key pair, made one current, retired one, trusted a certificate or
 * removed one, each carrying the summary of the key it acted on; or nothing,
 * because it was refused (`reason`) or what was given was invalid
 * (`violations`).
 *
 * A summary never holds a private key (SSO-2.5). A refusal is one of
 * `freshness_required`, `connection_not_found`, `key_not_found` and
 * `key_state_conflict`; an invalid result is `settings_invalid`, with at least
 * one `Connections\SettingViolation`, each naming a setting and a code, never a
 * value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class KeyResult implements \JsonSerializable
{
    /** @var list<\SineMacula\Laravel\Sso\Events\Enums\FailureReason> The reasons a key operation is refused for. */
    private const array REFUSALS = [
        FailureReason::FRESHNESS_REQUIRED,
        FailureReason::CONNECTION_NOT_FOUND,
        FailureReason::KEY_NOT_FOUND,
        FailureReason::KEY_STATE_CONFLICT,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @param  ?\SineMacula\Laravel\Sso\Keys\KeySummary  $previous
     * @param  ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     */
    private function __construct(

        /** How the operation ended. */
        public KeyStatus $status,

        /** The key or certificate acted on, as it is now, or as it was before it was removed. */
        public ?KeySummary $key = null,

        /** For `made_current`, the key it replaced, now retiring, when there was one. */
        public ?KeySummary $previous = null,

        /** Why the operation was refused, or `settings_invalid`. */
        public ?FailureReason $reason = null,

        /** What was refused of what was given, for `invalid`. */
        public array $violations = [],
    ) {}

    /**
     * A key pair was generated and added.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @return self
     */
    public static function added(KeySummary $key): self
    {
        return new self(KeyStatus::ADDED, $key);
    }

    /**
     * A key was made current, replacing the previous current key, now retiring,
     * when there was one.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @param  ?\SineMacula\Laravel\Sso\Keys\KeySummary  $previous
     * @return self
     */
    public static function madeCurrent(KeySummary $key, ?KeySummary $previous): self
    {
        return new self(KeyStatus::MADE_CURRENT, $key, $previous);
    }

    /**
     * A key was retired and removed; the summary is the key as it was.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @return self
     */
    public static function retired(KeySummary $key): self
    {
        return new self(KeyStatus::RETIRED, $key);
    }

    /**
     * A signing certificate of the identity provider is now trusted.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @return self
     */
    public static function trusted(KeySummary $key): self
    {
        return new self(KeyStatus::TRUSTED, $key);
    }

    /**
     * A trusted certificate was removed; the summary is the certificate as it
     * was.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeySummary  $key
     * @return self
     */
    public static function distrusted(KeySummary $key): self
    {
        return new self(KeyStatus::DISTRUSTED, $key);
    }

    /**
     * The operation was refused, and nothing was written.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason): self
    {
        if (!in_array($reason, self::REFUSALS, true)) {
            throw new \InvalidArgumentException(sprintf('A key operation is not refused for [%s].', $reason->value));
        }

        return new self(KeyStatus::REFUSED, reason: $reason);
    }

    /**
     * What was given was refused, and nothing was written.
     *
     * @param  list<\SineMacula\Laravel\Sso\Connections\SettingViolation>  $violations
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function invalid(array $violations): self
    {
        if ($violations === []) {
            throw new \InvalidArgumentException('An invalid result names at least one violation.');
        }

        return new self(KeyStatus::INVALID, reason: FailureReason::SETTINGS_INVALID, violations: $violations);
    }

    /**
     * Whether the change was made.
     *
     * @return bool
     */
    public function isSucceeded(): bool
    {
        return $this->status->isSucceeded();
    }

    /**
     * Whether the change was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status === KeyStatus::REFUSED;
    }

    /**
     * Whether what was given was refused.
     *
     * @return bool
     */
    public function isInvalid(): bool
    {
        return $this->status === KeyStatus::INVALID;
    }

    /**
     * The result, with snake_case keys: the status, the key and the previous
     * key as their summaries, the reason and the violations.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'status'     => $this->status->value,
            'key'        => $this->key?->jsonSerialize(),
            'previous'   => $this->previous?->jsonSerialize(),
            'reason'     => $this->reason?->value,
            'violations' => array_map(static fn (SettingViolation $violation): array => $violation->jsonSerialize(), $this->violations),
        ];
    }
}
