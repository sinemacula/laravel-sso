<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus;

/**
 * How a link's creation ended (SSO-8.4): `created`, with the link's summary; or
 * refused, with `subject_already_linked` or `link_limit_reached`.
 *
 * A refusal is a value, never thrown, and changed nothing: no link was written
 * and no event dispatched. It never says which identity holds a subject already
 * linked.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LinkCreation implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus  $status
     * @param  ?\SineMacula\Laravel\Sso\Links\LinkSummary  $link
     */
    private function __construct(

        /** How the creation ended. */
        public LinkCreationStatus $status,

        /** The link made, for `created` only. */
        public ?LinkSummary $link = null,
    ) {}

    /**
     * The link was made.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkSummary  $link
     * @return self
     */
    public static function created(LinkSummary $link): self
    {
        return new self(LinkCreationStatus::CREATED, $link);
    }

    /**
     * The issuer and subject are already linked in the connection.
     *
     * @return self
     */
    public static function subjectAlreadyLinked(): self
    {
        return new self(LinkCreationStatus::SUBJECT_ALREADY_LINKED);
    }

    /**
     * The identity holds as many links in the connection as it may.
     *
     * @return self
     */
    public static function linkLimitReached(): self
    {
        return new self(LinkCreationStatus::LINK_LIMIT_REACHED);
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
        return $this->status === LinkCreationStatus::CREATED;
    }

    /**
     * Whether the link was refused, with a reason.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->status !== LinkCreationStatus::CREATED;
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
