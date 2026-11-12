<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Provisioning;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus;

/**
 * How a provisioning call ended; a refusal wrote nothing but still spends the
 * grant, and never says which identity holds a linked subject.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProvisioningResult implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Links\LinkSummary  $link
     */
    private function __construct(

        /** How the call ended. */
        public ProvisioningStatus $status,

        /** The link made, for `created` only. */
        public ?LinkSummary $link = null,
    ) {}

    /**
     * The grant is not this dispatch's, or is used or closed.
     *
     * @return self
     */
    public static function grantInvalid(): self
    {
        return new self(ProvisioningStatus::GRANT_INVALID);
    }

    /**
     * The grant was given another result than it is bound to, and is spent.
     *
     * @return self
     */
    public static function grantWrongResult(): self
    {
        return new self(ProvisioningStatus::GRANT_WRONG_RESULT);
    }

    /**
     * The connection or the request no longer stands, under the locks.
     *
     * @return self
     */
    public static function requestUnavailable(): self
    {
        return new self(ProvisioningStatus::REQUEST_UNAVAILABLE);
    }

    /**
     * The verified response's deadline has passed.
     *
     * @return self
     */
    public static function expired(): self
    {
        return new self(ProvisioningStatus::EXPIRED);
    }

    /**
     * The subject is held in the connection.
     *
     * @return self
     */
    public static function subjectAlreadyLinked(): self
    {
        return new self(ProvisioningStatus::SUBJECT_ALREADY_LINKED);
    }

    /**
     * What the link store answered.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkCreation  $creation
     * @return self
     */
    public static function fromCreation(LinkCreation $creation): self
    {
        return match ($creation->status) {
            LinkCreationStatus::CREATED                => new self(ProvisioningStatus::CREATED, $creation->link),
            LinkCreationStatus::SUBJECT_ALREADY_LINKED => self::subjectAlreadyLinked(),
            LinkCreationStatus::LINK_LIMIT_REACHED     => new self(ProvisioningStatus::LINK_LIMIT_REACHED),
        };
    }

    /**
     * Why the link was not made, or `null` when it was.
     *
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public function reason(): ?FailureReason
    {
        return $this->status->reason();
    }

    /**
     * Whether the link was made.
     *
     * @return bool
     */
    public function isCreated(): bool
    {
        return $this->status === ProvisioningStatus::CREATED;
    }

    /**
     * Whether the call was refused.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status !== ProvisioningStatus::CREATED;
    }

    /**
     * Snake_case keys.
     *
     * @return array{status: string, link: ?array<string, mixed>, reason: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'status' => $this->status->value,
            'link'   => $this->link?->jsonSerialize(),
            'reason' => $this->reason()?->value,
        ];
    }
}
