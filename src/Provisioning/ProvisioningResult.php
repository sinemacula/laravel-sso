<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Provisioning;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Provisioning\Enums\ProvisioningStatus;

/**
 * How a call of the provisioning helper ended (SSO-8.6): `created`, with the
 * link's summary; or refused, with a status and the failure reason it carries.
 *
 * A refusal is a value, never thrown, and wrote nothing: no link was made and
 * no event dispatched, and the grant's one use is spent all the same. A
 * listener rolls its own transaction back on one. It never says which identity
 * holds a subject already linked, and a summary never holds the subject.
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
     * The grant is not this dispatch's, is used or closed, or is bound to
     * another result object.
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
     * Whether the call was refused, with a reason.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status !== ProvisioningStatus::CREATED;
    }

    /**
     * The result, with snake_case keys: the status, the link and the reason.
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
